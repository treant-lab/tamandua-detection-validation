from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/elixir_check_locked_probe.py"
SCHEMA = ROOT / "schemas/elixir_check_locked_probe_receipt_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("check_locked_probe", SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)
VALIDATOR = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))

IMAGE_A = "sha256:" + "a" * 64
IMAGE_B = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64
DEFAULT = object()
SECRET = "TOKEN=key-secret https://registry.invalid/pkg /host/path ENV=bad credential"


class FakeAdapter:
    evidence_marker = probe.TRUSTED_FAKE_EVIDENCE_MARKER

    def __init__(self, *, before=None, after=None, run_result=DEFAULT,
                 removed=True, absent=True, raise_at=()):
        self.before = [IMAGE_B, IMAGE_A] if before is None else before
        self.after = list(self.before) if after is None else after
        self.run_result = (
            probe.ProbeObservation(CONTAINER_ID, 1, SECRET) if run_result is DEFAULT else run_result
        )
        self.removed = removed
        self.absent = absent
        self.raise_at = set(raise_at)
        self.inventory_calls = 0
        self.run_calls = []
        self.remove_calls = []
        self.absent_calls = []

    def image_inventory(self):
        self.inventory_calls += 1
        phase = "inventory_before" if self.inventory_calls == 1 else "inventory_after"
        if phase in self.raise_at:
            raise RuntimeError(SECRET)
        return self.before if self.inventory_calls == 1 else self.after

    def run_once(self, argv):
        self.run_calls.append(tuple(argv))
        if "run" in self.raise_at:
            raise RuntimeError(SECRET)
        return self.run_result

    def remove_container(self, name):
        self.remove_calls.append(name)
        if "remove" in self.raise_at:
            raise RuntimeError(SECRET)
        return self.removed

    def container_absent(self, name):
        self.absent_calls.append(name)
        if "absent" in self.raise_at:
            raise RuntimeError(SECRET)
        return self.absent


def receipt(adapter=None):
    return probe.build_receipt(adapter or FakeAdapter())


def assert_private(value):
    serialized = json.dumps(value).lower()
    for forbidden in ("credential", "token=", "key-secret", "https://", "registry.invalid", "/host/path", "env=bad"):
        assert forbidden not in serialized


def test_successful_fake_adapter_contract_is_bound_private_and_one_call_only():
    adapter = FakeAdapter()
    result = receipt(adapter)
    VALIDATOR.validate(result)
    probe.validate_receipt(result)
    assert result["result"]["status"] == "observed"
    assert result["cleanup"]["complete"] is True
    assert result["container"]["id"] == CONTAINER_ID
    assert result["evidence_boundary"]["adapter_trust"] == "trusted_injected_fake"
    assert result["evidence_boundary"]["validation_scope"] == "unit_test_and_accidental_drift_only"
    assert result["evidence_boundary"]["real_adapter_allowed"] is False
    assert result["evidence_boundary"]["required_before_real_adapter"] == [
        "separate_process_boundary", "serialized_immutable_manifest",
    ]
    assert all(value is False for value in result["claims"].values())
    assert result["metrics"] == {
        "adapter_contract": "trusted_injected_fake_v1",
        "interface_calls": {
            "image_inventory": 2, "run_once": 1,
            "remove_container_by_name": 1, "container_absent_by_name": 1,
        },
    }
    assert adapter.remove_calls == adapter.absent_calls == [result["container"]["name"]]
    assert len(adapter.run_calls) == 1
    assert_private(result)


def test_caller_cannot_supply_invocation_id_or_broad_bindings():
    with pytest.raises(TypeError):
        probe.build_receipt(FakeAdapter(), "loop144-abcdef1234567890")


def test_invocation_ids_are_internal_64_bit_shaped_values_without_entropy_claim():
    first = receipt()["invocation"]["id"]
    second = receipt()["invocation"]["id"]
    assert probe.INVOCATION.fullmatch(first)
    assert probe.INVOCATION.fullmatch(second)
    assert len(first.removeprefix("loop144-")) * 4 == 64
    assert first != second
    assert receipt()["evidence_boundary"]["invocation_entropy_verified"] is False


@pytest.mark.parametrize("target", ["token_hex", "sha256"])
def test_primitive_drift_fails_before_adapter_inspection(monkeypatch, target):
    class UntouchableAdapter:
        @property
        def image_inventory(self):
            raise AssertionError("adapter must not be inspected")

    module = probe.secrets if target == "token_hex" else probe.hashlib
    monkeypatch.setattr(module, target, lambda *_args, **_kwargs: "0" * 16)
    with pytest.raises(ValueError, match="precall_primitive_drift"):
        probe.build_receipt(UntouchableAdapter())


@pytest.mark.parametrize(
    ("constant", "value", "error_class"),
    [
        ("SOURCE_HEAD", "credential", "closed_source_head_invalid"),
        ("MIX_LOCK_SHA256", "sk_test_unsafe", "closed_digest_invalid"),
        ("HYDRATOR_IMAGE_ID", "latest", "closed_image_id_invalid"),
        ("CONFIG_FILE_COUNT", True, "closed_config_file_count_invalid"),
        ("TOOLCHAIN_PROFILE", "credential", "closed_binding_mismatch"),
        ("PROFILE", "sk_test_deadbeef", "closed_binding_mismatch"),
        ("SOURCE_HEAD", "0" * 40, "closed_binding_mismatch"),
        ("HYDRATOR_IMAGE_ID", IMAGE_A, "closed_binding_mismatch"),
        ("TOOLCHAIN_PROFILE", "other-profile", "closed_binding_mismatch"),
        ("EVIDENCE_CLASS", "other-local-class", "closed_binding_mismatch"),
        ("EVIDENCE_BOUNDARY", (), "closed_binding_mismatch"),
        ("PARENT_LOOP", 138, "closed_binding_mismatch"),
        ("ADAPTER_CONTRACT", "injected_fake_v2", "closed_binding_mismatch"),
        ("LIMITATIONS", ("drift",), "closed_binding_mismatch"),
        ("FALSE_CLAIMS", {"product_ready": True}, "closed_binding_mismatch"),
        ("LOCKED_PRECONDITION_LINE_SHA256", "0" * 64, "closed_binding_mismatch"),
        ("FORBIDDEN_PERSISTED_PATTERNS", (), "closed_privacy_policy_mismatch"),
        ("INVOCATION", probe.re.compile(r"^loop144-.+$"), "closed_invocation_policy_mismatch"),
        ("SCHEMA_FILE_SHA256", "0" * 64, "schema_hash_mismatch"),
        ("_validate_finalization", lambda **_kwargs: None, "precall_primitive_drift"),
        ("_validate_primary_result", lambda **_kwargs: None, "precall_primitive_drift"),
        ("_validate_receipt_with_snapshot", lambda *_args: None, "precall_primitive_drift"),
    ],
)
def test_closed_persisted_values_are_validated_before_adapter_inspection(
    monkeypatch, constant, value, error_class,
):
    class UntouchableAdapter:
        @property
        def image_inventory(self):
            raise AssertionError("adapter must not be inspected")

    monkeypatch.setattr(probe, constant, value)
    with pytest.raises(ValueError, match=error_class):
        probe.build_receipt(UntouchableAdapter())


@pytest.mark.parametrize(
    ("schema_value", "error_class"),
    [
        ({"type": 7}, "schema_structure_invalid"),
        ({**json.loads(SCHEMA.read_text(encoding="utf-8")), "title": "drift"}, "schema_hash_mismatch"),
    ],
)
def test_schema_structure_and_hash_drift_fail_before_adapter_inspection(
    tmp_path, monkeypatch, schema_value, error_class,
):
    drift = tmp_path / "drift.schema.json"
    drift.write_text(json.dumps(schema_value), encoding="utf-8")

    class UntouchableAdapter:
        @property
        def image_inventory(self):
            raise AssertionError("adapter must not be inspected")

    monkeypatch.setattr(probe, "SCHEMA", drift)
    with pytest.raises(ValueError, match=error_class):
        probe.build_receipt(UntouchableAdapter())


def test_accidental_drift_snapshot_is_frozen_without_adversarial_evidence_claim():
    snapshot = probe._load_run_snapshot()
    with pytest.raises((AttributeError, TypeError)):
        snapshot.invocation_id = "loop144-0000000000000000"
    with pytest.raises(TypeError):
        snapshot.values["profile"] = "drift"
    assert isinstance(snapshot.values["limitations"], tuple)
    assert isinstance(snapshot.values["claims"], tuple)
    with pytest.raises(TypeError, match="immutable_snapshot"):
        snapshot.schema_validator.schema["type"] = "integer"
    with pytest.raises(TypeError, match="immutable_snapshot"):
        snapshot.schema_validator.schema["required"].append("drift")


def test_same_interpreter_regression_attack_cannot_promote_evidence(tmp_path, monkeypatch):
    drift = tmp_path / "late-drift.schema.json"
    drift.write_text('{"type": 7}', encoding="utf-8")

    with monkeypatch.context() as mutation:
        class MutatingAdapter(FakeAdapter):
            def image_inventory(self):
                if self.inventory_calls == 0:
                    mutation.setattr(probe, "SCHEMA", drift)
                    mutation.setattr(probe, "PROFILE", "sk_test_late_drift")
                    mutation.setattr(probe, "SOURCE_HEAD", "0" * 40)
                    mutation.setattr(probe, "LOCKED_PRECONDITION_LINE_SHA256", "0" * 64)
                    mutation.setattr(probe, "FORBIDDEN_PERSISTED_PATTERNS", ())
                    mutation.setattr(probe, "SHA256", probe.re.compile(r".*"))
                    mutation.setattr(probe, "IMAGE_ID", probe.re.compile(r".*"))
                    mutation.setattr(probe, "CONTAINER_ID", probe.re.compile(r".*"))
                    mutation.setattr(probe, "digest", lambda _value: "0" * 64)
                    mutation.setattr(probe, "line_digest", lambda _value: "0" * 64)
                    mutation.setattr(probe, "failure_class_for_digest", lambda _value: "drift")
                    mutation.setattr(probe, "_validate_finalization", lambda **_kwargs: None)
                    mutation.setattr(probe, "_validate_primary_result", lambda **_kwargs: None)
                    mutation.setattr(probe, "Draft202012Validator", lambda _schema: None)
                    mutation.setattr(type(VALIDATOR), "validate", lambda _self, _value: None)
                    mutation.setattr(probe.secrets, "token_hex", lambda _size: "0" * 16)
                return super().image_inventory()

        result = receipt(MutatingAdapter())
    VALIDATOR.validate(result)
    assert result["profile"] == "elixir-check-locked-auditable-probe-v1"
    assert result["evidence_class"] == "local_offline_trusted_fake_unit_test_contract"
    assert result["evidence_boundary"] == {
        "adapter_trust": "trusted_injected_fake",
        "validation_scope": "unit_test_and_accidental_drift_only",
        "same_interpreter_adversarial_resistance_proven": False,
        "schema_provenance_verified": False,
        "invocation_entropy_verified": False,
        "real_cleanup_verified": False,
        "real_adapter_allowed": False,
        "required_before_real_adapter": [
            "separate_process_boundary", "serialized_immutable_manifest",
        ],
    }
    assert result["inputs"]["source_head"] == "ce97ccd64a686e91fbf6f613e3face7cb17843d2"
    assert result["result"]["failure_line_sha256"] == probe.hashlib.sha256(
        SECRET.encode("utf-8"),
    ).hexdigest()
    assert result["result"]["failure_class"] == "unclassified"
    assert result["cleanup"]["complete"] is True


def test_adapter_contract_is_prevalidated_before_any_call():
    class MissingMethods:
        evidence_marker = probe.TRUSTED_FAKE_EVIDENCE_MARKER

        def image_inventory(self):
            raise AssertionError("must not call")

    with pytest.raises(ValueError, match="adapter_contract_invalid"):
        probe.build_receipt(MissingMethods())


@pytest.mark.parametrize("marker", [None, "trusted_fake_unit_test", object()])
def test_unmarked_or_forged_fake_adapter_is_rejected_before_interface_calls(marker):
    adapter = FakeAdapter()
    adapter.evidence_marker = marker
    with pytest.raises(ValueError, match="adapter_not_trusted_fake"):
        probe.build_receipt(adapter)
    assert adapter.inventory_calls == 0
    assert adapter.run_calls == adapter.remove_calls == adapter.absent_calls == []


def test_marker_getter_cannot_replace_the_captured_trusted_identity(monkeypatch):
    class MarkerSwappingAdapter(FakeAdapter):
        @property
        def evidence_marker(self):
            replacement = object()
            monkeypatch.setattr(probe, "TRUSTED_FAKE_EVIDENCE_MARKER", replacement)
            return replacement

    adapter = MarkerSwappingAdapter()
    with pytest.raises(ValueError, match="adapter_not_trusted_fake"):
        probe.build_receipt(adapter)
    assert adapter.inventory_calls == 0
    assert adapter.run_calls == adapter.remove_calls == adapter.absent_calls == []


def test_adapter_functions_are_captured_once_before_calls_and_constructor_drift(monkeypatch):
    class OneShotAdapter:
        evidence_marker = probe.TRUSTED_FAKE_EVIDENCE_MARKER

        def __init__(self):
            self.inspections = {name: 0 for name in (
                "image_inventory", "run_once", "remove_container", "container_absent",
            )}
            self.inventory_calls = 0

        def capture(self, name, function):
            self.inspections[name] += 1
            if self.inspections[name] != 1:
                raise AssertionError(f"{name} inspected more than once")
            return function

        @property
        def image_inventory(self):
            monkeypatch.setattr(probe, "AdapterSnapshot", lambda **_kwargs: None)

            def inventory():
                self.inventory_calls += 1
                return [IMAGE_A]

            return self.capture("image_inventory", inventory)

        @property
        def run_once(self):
            return self.capture(
                "run_once", lambda _argv: probe.ProbeObservation(CONTAINER_ID, 1, "failure"),
            )

        @property
        def remove_container(self):
            return self.capture("remove_container", lambda _name: True)

        @property
        def container_absent(self):
            return self.capture("container_absent", lambda _name: True)

    adapter = OneShotAdapter()
    result = receipt(adapter)
    assert all(count == 1 for count in adapter.inspections.values())
    assert adapter.inventory_calls == 2
    assert result["cleanup"]["complete"] is True


def test_adapter_property_exception_is_categorical_before_any_interface_call():
    class HostileAdapter:
        evidence_marker = probe.TRUSTED_FAKE_EVIDENCE_MARKER

        @property
        def image_inventory(self):
            raise RuntimeError(SECRET)

    with pytest.raises(ValueError, match="adapter_contract_invalid") as error:
        probe.build_receipt(HostileAdapter())
    assert SECRET not in str(error.value)


@pytest.mark.parametrize(
    ("run_result", "error_class"),
    [
        (None, "observation_invalid"),
        (probe.ProbeObservation(SECRET, 1, "failure"), "container_id_invalid"),
        (probe.ProbeObservation(CONTAINER_ID, 0, "failure"), "exit_code_invalid"),
        (probe.ProbeObservation(CONTAINER_ID, 126, "failure"), "exit_code_invalid"),
        (probe.ProbeObservation(CONTAINER_ID, 1, "first\nsecond " + SECRET), "failure_line_invalid"),
    ],
)
def test_malformed_run_results_are_categorical_private_and_always_finalized_by_name(run_result, error_class):
    adapter = FakeAdapter(run_result=run_result)
    result = receipt(adapter)
    assert result["result"]["status"] == "blocked"
    assert result["result"]["error_class"] == error_class
    assert result["container"]["id"] is None or result["container"]["id"] == CONTAINER_ID
    assert adapter.remove_calls == adapter.absent_calls == [result["container"]["name"]]
    assert result["metrics"]["interface_calls"]["run_once"] == 1
    assert_private(result)


def test_run_exception_is_categorical_and_independent_finalizers_still_run():
    adapter = FakeAdapter(raise_at={"run"})
    result = receipt(adapter)
    assert result["result"]["error_class"] == "run_adapter_error"
    assert adapter.remove_calls == adapter.absent_calls == [result["container"]["name"]]
    assert adapter.inventory_calls == 2
    assert result["container"]["id"] is None
    assert_private(result)


@pytest.mark.parametrize(
    ("raise_at", "expected"),
    [
        ({"remove"}, "remove_adapter_error"),
        ({"absent"}, "absence_adapter_error"),
        ({"remove", "absent"}, "remove_adapter_error"),
        ({"inventory_after"}, "inventory_after_error"),
        ({"remove", "inventory_after"}, "remove_adapter_error"),
    ],
)
def test_finalization_exceptions_are_independent_categorical_and_private(raise_at, expected):
    adapter = FakeAdapter(raise_at=raise_at)
    result = receipt(adapter)
    assert expected in result["result"]["finalization_errors"]
    assert result["cleanup"]["complete"] is False
    assert len(adapter.remove_calls) == len(adapter.absent_calls) == 1
    assert adapter.inventory_calls == 2
    assert_private(result)


@pytest.mark.parametrize(
    ("removed", "absent", "expected"),
    [(None, True, "remove_result_invalid"), (True, None, "absence_result_invalid"),
     (False, True, "remove_incomplete"), (True, False, "container_still_present")],
)
def test_finalization_malformed_or_negative_results_are_categorical(removed, absent, expected):
    result = receipt(FakeAdapter(removed=removed, absent=absent))
    assert expected in result["result"]["finalization_errors"]
    assert result["cleanup"]["complete"] is False


def test_inventory_before_exception_blocks_run_and_does_not_claim_cleanup_calls():
    adapter = FakeAdapter(raise_at={"inventory_before"})
    result = receipt(adapter)
    assert result["result"]["error_class"] == "inventory_before_error"
    assert result["execution"]["run_attempted"] is False
    assert adapter.run_calls == adapter.remove_calls == adapter.absent_calls == []
    assert result["metrics"]["interface_calls"] == {
        "image_inventory": 2, "run_once": 0,
        "remove_container_by_name": 0, "container_absent_by_name": 0,
    }
    assert_private(result)


@pytest.mark.parametrize("inventory", [[IMAGE_A, IMAGE_A], [SECRET], ["latest"]])
def test_invalid_before_inventory_is_sanitized_and_blocks_run(inventory):
    adapter = FakeAdapter(before=inventory)
    result = receipt(adapter)
    assert result["result"]["error_class"] == "inventory_before_error"
    assert result["inventory"]["before"] == {"status": "adapter_error", "manifest": [], "manifest_sha256": None}
    assert adapter.run_calls == []
    assert_private(result)


def test_inventory_drift_is_categorical_and_cleanup_incomplete():
    result = receipt(FakeAdapter(after=[IMAGE_A]))
    assert result["inventory"]["unchanged"] is False
    assert "inventory_changed" in result["result"]["finalization_errors"]
    assert result["cleanup"]["complete"] is False


def test_all_failure_and_finalization_paths_remain_non_promoting_trusted_fake_evidence():
    adapters = [
        FakeAdapter(raise_at={"inventory_before"}),
        FakeAdapter(raise_at={"run"}),
        FakeAdapter(removed=False),
        FakeAdapter(absent=False),
        FakeAdapter(after=[IMAGE_A]),
    ]
    for adapter in adapters:
        result = receipt(adapter)
        assert result["evidence_class"] == "local_offline_trusted_fake_unit_test_contract"
        assert result["evidence_boundary"]["adapter_trust"] == "trusted_injected_fake"
        assert result["evidence_boundary"]["real_adapter_allowed"] is False
        assert result["evidence_boundary"]["real_cleanup_verified"] is False
        assert all(value is False for value in result["claims"].values())
        assert_private(result)


def test_exact_argv_digests_inventory_parent_inputs_and_toolchain_remain_bound():
    result = receipt()
    assert result["invocation"]["argv_sha256"] == probe.digest(result["invocation"]["argv"])
    assert result["parent"] == {"loop": 137, "artifact_sha256": probe.PARENT_LOOP137_SHA256}
    assert result["inventory"]["before"]["manifest"] == [IMAGE_A, IMAGE_B]
    assert result["inventory"]["before"]["manifest_sha256"] == probe.digest([IMAGE_A, IMAGE_B])
    assert result["inputs"]["source_head"] == probe.SOURCE_HEAD
    assert result["inputs"]["hydrator_image_id"] == probe.HYDRATOR_IMAGE_ID
    assert result["toolchain"]["profile"] == probe.TOOLCHAIN_PROFILE
    assert not any("/" in item or "\\" in item or "env=" in item.lower() for item in result["invocation"]["argv"])


@pytest.mark.parametrize("mutator", [
    lambda value: value["invocation"].__setitem__("argv_sha256", "0" * 64),
    lambda value: value["container"].__setitem__("name", "tamandua-check-locked-loop144-0000000000000000"),
    lambda value: value["inventory"]["before"].__setitem__("manifest_sha256", "0" * 64),
    lambda value: value["result"].__setitem__("failure_class", "locked_state_precondition_rejected"),
    lambda value: value["cleanup"].__setitem__("complete", False),
    lambda value: value["metrics"]["interface_calls"].__setitem__("run_once", 0),
    lambda value: value["metrics"]["interface_calls"].__setitem__("image_inventory", 1),
    lambda value: value["metrics"]["interface_calls"].__setitem__("remove_container_by_name", 0),
    lambda value: value["result"]["finalization_errors"].append("remove_adapter_error"),
    lambda value: value["inventory"]["after"].update({"status": "adapter_error", "manifest": [], "manifest_sha256": None}),
    lambda value: value["result"].__setitem__("status", "blocked"),
    lambda value: value["result"].__setitem__("outcome", "unknown"),
])
def test_semantic_validator_rejects_cross_field_and_metric_drift(mutator):
    value = copy.deepcopy(receipt())
    mutator(value)
    with pytest.raises((ValueError, ValidationError)):
        probe.validate_receipt(value)


@pytest.mark.parametrize("mutator", [
    lambda value: value.__setitem__("raw_logs", SECRET),
    lambda value: value["result"].__setitem__("raw_output_persisted", True),
    lambda value: value["execution"].__setitem__("retried", True),
    lambda value: value["execution"].__setitem__("network_requested", True),
    lambda value: value["claims"].__setitem__("product_ready", True),
    lambda value: value["evidence_boundary"].__setitem__("real_adapter_allowed", True),
    lambda value: value["evidence_boundary"].__setitem__("real_cleanup_verified", True),
    lambda value: value["evidence_boundary"].__setitem__("invocation_entropy_verified", True),
    lambda value: value["evidence_boundary"].__setitem__("schema_provenance_verified", True),
    lambda value: value["evidence_boundary"].__setitem__("same_interpreter_adversarial_resistance_proven", True),
    lambda value: value["evidence_boundary"].__setitem__("adapter_trust", "real_adapter"),
    lambda value: value["evidence_boundary"].__setitem__("validation_scope", "adversarial_proof"),
    lambda value: value["evidence_boundary"].__setitem__("required_before_real_adapter", []),
    lambda value: value.__setitem__("evidence_class", "real_adapter_evidence"),
    lambda value: value["metrics"].__setitem__("container_runs", 1),
    lambda value: value["inputs"].__setitem__("source_head", "0" * 40),
    lambda value: value["inputs"].__setitem__("hydrator_image_id", IMAGE_A),
    lambda value: value["toolchain"].__setitem__("profile", "other-profile"),
])
def test_schema_rejects_raw_retry_network_claim_and_noninterface_metrics(mutator):
    value = copy.deepcopy(receipt())
    mutator(value)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(value)


def test_semantic_validator_rejects_missing_or_wrong_finalization_markers():
    cases = []
    remove_failed = receipt(FakeAdapter(removed=False))
    remove_failed["result"]["finalization_errors"] = []
    cases.append(remove_failed)
    absence_failed = receipt(FakeAdapter(absent=False))
    absence_failed["result"]["finalization_errors"] = ["absence_adapter_error"]
    cases.append(absence_failed)
    inventory_failed = receipt(FakeAdapter(raise_at={"inventory_after"}))
    inventory_failed["result"]["finalization_errors"] = []
    cases.append(inventory_failed)
    for value in cases:
        with pytest.raises((ValueError, ValidationError)):
            probe.validate_receipt(value)


def test_semantic_validator_rejects_primary_error_field_spoofing():
    cases = []
    run_error = receipt(FakeAdapter(raise_at={"run"}))
    run_error["container"]["id"] = CONTAINER_ID
    cases.append(run_error)
    exit_error = receipt(FakeAdapter(run_result=probe.ProbeObservation(CONTAINER_ID, 0, "failure")))
    exit_error["container"]["id"] = None
    cases.append(exit_error)
    line_error = receipt(FakeAdapter(run_result=probe.ProbeObservation(CONTAINER_ID, 1, "first\nsecond")))
    line_error["result"]["exit_code"] = None
    cases.append(line_error)
    for value in cases:
        with pytest.raises((ValueError, ValidationError)):
            probe.validate_receipt(value)


def test_helper_has_no_real_process_or_network_adapter():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "import subprocess" not in source and "subprocess." not in source
    assert "import socket" not in source and "os.system" not in source
    assert '["docker", "run"' not in source
