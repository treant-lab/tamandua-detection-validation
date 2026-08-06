import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "runtime_self_image_page_plan_gate.py"
SCHEMA = ROOT / "schemas" / "runtime_self_image_page_plan_receipt_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("runtime_self_image_page_plan_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GATE)


def pe_fixture() -> bytes:
    data = bytearray(0x1400)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff:coff + 2] = (0x8664).to_bytes(2, "little")
    data[coff + 2:coff + 4] = (1).to_bytes(2, "little")
    data[coff + 16:coff + 18] = (240).to_bytes(2, "little")
    data[coff + 18:coff + 20] = (0x22).to_bytes(2, "little")
    optional = coff + 20
    data[optional:optional + 2] = (0x20B).to_bytes(2, "little")
    data[optional + 32:optional + 36] = (4096).to_bytes(4, "little")
    data[optional + 36:optional + 40] = (512).to_bytes(4, "little")
    data[optional + 56:optional + 60] = (8192).to_bytes(4, "little")
    data[optional + 60:optional + 64] = (512).to_bytes(4, "little")
    data[optional + 108:optional + 112] = (0).to_bytes(4, "little")
    section = optional + 240
    data[section:section + 5] = b".text"
    data[section + 8:section + 12] = (4096).to_bytes(4, "little")
    data[section + 12:section + 16] = (4096).to_bytes(4, "little")
    data[section + 16:section + 20] = (4096).to_bytes(4, "little")
    data[section + 20:section + 24] = (0x400).to_bytes(4, "little")
    data[section + 36:section + 40] = (0x60000020).to_bytes(4, "little")
    return bytes(data)


class RuntimeSelfImagePagePlanGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "owned.exe"
        self.artifact.write_bytes(pe_fixture())
        self.planner = self.root / "page_content.rs"
        self.planner.write_bytes(b"planner identity")
        self.harness = self.root / "harness.exe"
        self.harness.write_bytes(b"harness identity")
        digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.receipt = {
            "artifact_sha256_after": digest,
            "artifact_sha256_before": digest,
            "artifact_size": len(self.artifact.read_bytes()),
            "bounds": {"max_eligible_bytes": 33554432, "max_input_bytes": 67108864},
            "build_command_id": "cargo-release-windows-x86_64-msvc",
            "claims": {
                "external_claim_allowed": False,
                "live_memory_compared": False,
                "release_authority": False,
                "runtime_detection_proven": False,
                "telemetry_emitted": False,
            },
            "eligible_bytes": 4096,
            "eligible_pages": 1,
            "evidence_class": "owned-artifact-static-smoke",
            "executable_file_backed_bytes": 4096,
            "format": "pe64-amd64",
            "harness_sha256": hashlib.sha256(self.harness.read_bytes()).hexdigest(),
            "page_size": 4096,
            "planner_source_sha256": hashlib.sha256(self.planner.read_bytes()).hexdigest(),
            "relocation_excluded_pages": 0,
            "schema_version": "tamandua.runtime_self_image_page_plan_receipt/v1",
            "target": "x86_64-pc-windows-msvc",
        }

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, value=None):
        path = self.root / "receipt.json"
        path.write_text(json.dumps(self.receipt if value is None else value,
                                   separators=(",", ":"), sort_keys=True), encoding="utf-8")
        return path

    def validate(self, value=None, artifact=None):
        return GATE.validate(
            self.write(value), artifact or self.artifact, SCHEMA,
            self.planner, self.harness,
        )

    def assert_rejected(self, value=None, artifact=None):
        with self.assertRaises(GATE.GateError):
            self.validate(value, artifact)

    def test_accepts_exact_strong_receipt_with_required_identity_inputs(self):
        self.assertEqual(self.validate()["eligible_pages"], 1)

    def test_rejects_before_after_transplant_tamper_and_changed_artifact(self):
        for field in ("artifact_sha256_before", "artifact_sha256_after"):
            hostile = copy.deepcopy(self.receipt)
            hostile[field] = "0" * 64
            self.assert_rejected(hostile)
        other = self.root / "other.exe"
        other.write_bytes(pe_fixture()[:-1] + b"X")
        self.assert_rejected(artifact=other)
        self.artifact.write_bytes(self.artifact.read_bytes() + b"changed")
        self.assert_rejected()

    def test_rejects_source_and_harness_hash_type_normalization_or_stale_identity(self):
        for field in ("planner_source_sha256", "harness_sha256"):
            for value in (True, "A" * 64, "0" * 63):
                hostile = copy.deepcopy(self.receipt)
                hostile[field] = value
                self.assert_rejected(hostile)
        hostile = copy.deepcopy(self.receipt)
        hostile["planner_source_sha256"] = "0" * 64
        self.assert_rejected(hostile)

    def test_rejects_boolean_and_integer_type_confusion(self):
        for field in ("artifact_size", "eligible_pages", "eligible_bytes", "page_size"):
            hostile = copy.deepcopy(self.receipt)
            hostile[field] = True
            self.assert_rejected(hostile)
        hostile = copy.deepcopy(self.receipt)
        hostile["claims"]["telemetry_emitted"] = 0
        self.assert_rejected(hostile)

    def test_rejects_external_claim_or_any_other_true_claim(self):
        for field in GATE.CLAIM_KEYS:
            hostile = copy.deepcopy(self.receipt)
            hostile["claims"][field] = True
            self.assert_rejected(hostile)

    def test_rejects_privacy_risk_and_unknown_fields(self):
        for key, value in (
            ("artifact_path", "C:/secret/app.exe"), ("virtual_addresses", [4096]),
            ("page_hashes", ["0" * 64]), ("raw_bytes", "4d5a"), ("file_offsets", [0]),
        ):
            hostile = copy.deepcopy(self.receipt)
            hostile[key] = value
            self.assert_rejected(hostile)

    def test_rejects_target_format_and_build_command_mismatch(self):
        for field, value in (
            ("format", "macho64-x86_64"), ("target", "aarch64-apple-darwin"),
            ("build_command_id", "cargo-release-macos-x86_64"),
        ):
            hostile = copy.deepcopy(self.receipt)
            hostile[field] = value
            self.assert_rejected(hostile)

    def test_rejects_impossible_counts_bounds_and_executable_aggregate(self):
        for field, value in (
            ("eligible_pages", 0), ("eligible_pages", 8193), ("eligible_bytes", 8192),
            # This mutation passes the coarse size arithmetic but must fail the
            # independent PE relocation/IAT page derivation.
            ("relocation_excluded_pages", 1), ("artifact_size", 67108865),
            ("executable_file_backed_bytes", 2048),
            ("executable_file_backed_bytes", len(pe_fixture()) + 1),
        ):
            hostile = copy.deepcopy(self.receipt)
            hostile[field] = value
            self.assert_rejected(hostile)
        hostile = copy.deepcopy(self.receipt)
        hostile["bounds"]["max_input_bytes"] = 1
        self.assert_rejected(hostile)

    def test_rejects_noncanonical_json_and_schema_is_strict(self):
        path = self.root / "receipt.json"
        path.write_text(json.dumps(self.receipt, indent=2), encoding="utf-8")
        with self.assertRaises(GATE.GateError):
            GATE.validate(path, self.artifact, SCHEMA, self.planner, self.harness)
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), GATE.ROOT_KEYS)
        self.assertEqual(set(schema["properties"]), GATE.ROOT_KEYS)


if __name__ == "__main__":
    unittest.main()
