from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "run_hist256_runtime_parity.py"
SPEC = importlib.util.spec_from_file_location("hist256_runtime_parity", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, list[str]]:
    good, bad = b"goodware-parity", b"maki-malware-parity"
    good_sha, bad_sha = hashlib.sha256(good).hexdigest(), hashlib.sha256(bad).hexdigest()
    good_root, bad_root = tmp_path / "good", tmp_path / "maki"
    good_root.mkdir(); bad_root.mkdir()
    (good_root / f"{good_sha}.bin").write_bytes(good)
    (bad_root / f"{bad_sha}.bin").write_bytes(bad)
    members = sorted(((good_sha, 0), (bad_sha, 1)))
    membership = tmp_path / "membership.jsonl"
    membership.write_bytes(b"".join(_canonical({"label": label, "sha256": sha}) for sha, label in members))
    membership_sha = hashlib.sha256(membership.read_bytes()).hexdigest()
    manifest = tmp_path / "samples.json"
    manifest.write_bytes(_canonical({
        "api_version": MODULE.MANIFEST_VERSION,
        "evidence_class": "runtime_parity_smoke", "used_split": "train",
        "holdout_opened": False, "efficacy_claim_allowed": False,
        "training_membership_sha256": membership_sha,
        "samples": [
            {"sha256": good_sha, "label": 0, "root_id": "goodware"},
            {"sha256": bad_sha, "label": 1, "root_id": "maki"},
        ],
    }))
    artifact = tmp_path / "model.txt"
    artifact.write_bytes(b"tree\nversion=v4\nmax_feature_idx=255\nend of trees\n")
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    registry = tmp_path / "providers.json"
    registry.write_bytes(_canonical({
        "schema_version": MODULE.REGISTRY_VERSION,
        "policy": {"enabled_default": False, "remote_bind_allowed": False,
                   "remote_download_allowed": False, "enforcement_allowed": False},
        "providers": [{
            "provider_id": "hist256", "model_contract_id": "tamandua.hist256.test",
            "implementation": "lightgbm_local", "enabled": False,
            "evidence_class": "bootstrap_shadow_calibration", "decision_mode": "endpoint_shadow",
            "max_file_bytes": 4096, "artifact_sha256": artifact_sha,
            "artifact_size_bytes": artifact.stat().st_size,
            "feature_contract_id": MODULE.FEATURE_CONTRACT_ID, "feature_dimension": 256,
            "score_orientation": "higher_is_more_malicious",
        }],
    }))
    return registry, artifact, manifest, membership, [f"goodware={good_root}", f"maki={bad_root}"]


def test_capture_and_compare_are_parity_only_and_sealed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, artifact, manifest, membership, roots = _fixture(tmp_path)

    class Booster:
        def __init__(self, *, model_str: str) -> None:
            assert "version=v4" in model_str
        def predict(self, rows: list[list[float]]) -> list[float]:
            return [sum(index * value for index, value in enumerate(rows[0])) / 255]

    monkeypatch.setitem(sys.modules, "lightgbm", SimpleNamespace(Booster=Booster))
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda _: "4.5.0")
    left = MODULE.capture(
        registry_path=registry, artifact_path=artifact, sample_manifest_path=manifest,
        membership_path=membership, sample_roots=roots, expected_lightgbm_version="4.5.0")
    left_path, right_path = tmp_path / "left.json", tmp_path / "right.json"
    left_path.write_bytes(_canonical(left))
    # Replay is deliberately feature-only: raw goodware/malware roots may be absent.
    shutil.rmtree(tmp_path / "good")
    shutil.rmtree(tmp_path / "maki")
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda _: "4.6.0")
    right = MODULE.replay(
        source_capture_path=left_path, registry_path=registry, artifact_path=artifact,
        expected_source_version="4.5.0", expected_lightgbm_version="4.6.0")
    right_path.write_bytes(_canonical(right))
    evidence = MODULE.compare(
        left_path=left_path, right_path=right_path,
        expected_versions=("4.5.0", "4.6.0"), max_delta=0.0)
    assert evidence["status"] == "passed"
    assert evidence["sample_count"] == 2
    assert evidence["max_observed_absolute_score_delta"] == 0
    assert evidence["holdout_opened"] is False
    assert evidence["efficacy_claim_allowed"] is False
    assert evidence["promotion_eligible"] is False
    assert evidence["enforcement_allowed"] is False
    assert right["source_capture_sha256"] == hashlib.sha256(left_path.read_bytes()).hexdigest()


def test_capture_rejects_body_outside_pinned_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, artifact, manifest, membership, roots = _fixture(tmp_path)
    value = json.loads(manifest.read_text())
    value["samples"][0]["sha256"] = "f" * 64
    manifest.write_bytes(_canonical(value))
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda _: "4.5.0")
    monkeypatch.setitem(sys.modules, "lightgbm", SimpleNamespace(Booster=object))
    with pytest.raises(MODULE.RuntimeParityError, match="exact member"):
        MODULE.capture(
            registry_path=registry, artifact_path=artifact, sample_manifest_path=manifest,
            membership_path=membership, sample_roots=roots, expected_lightgbm_version="4.5.0")


def test_compare_rejects_tampered_capture(tmp_path: Path) -> None:
    value = {
        "api_version": MODULE.CAPTURE_VERSION, "evidence_class": "runtime_parity_smoke",
        "holdout_opened": False, "efficacy_claim_allowed": False,
        "enforcement_allowed": False, "samples": [], "capture_sha256": "0" * 64,
    }
    left = tmp_path / "left.json"; right = tmp_path / "right.json"
    left.write_bytes(_canonical(value)); right.write_bytes(_canonical(value))
    with pytest.raises(MODULE.RuntimeParityError, match="seal"):
        MODULE.compare(
            left_path=left, right_path=right,
            expected_versions=("4.5.0", "4.6.0"), max_delta=1e-12)


def test_replay_rejects_resealed_but_tampered_feature_vector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, artifact, manifest, membership, roots = _fixture(tmp_path)

    class Booster:
        def __init__(self, *, model_str: str) -> None:
            assert model_str
        def predict(self, rows: list[list[float]]) -> list[float]:
            return [0.5]

    monkeypatch.setitem(sys.modules, "lightgbm", SimpleNamespace(Booster=Booster))
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda _: "4.5.0")
    source = MODULE.capture(
        registry_path=registry, artifact_path=artifact, sample_manifest_path=manifest,
        membership_path=membership, sample_roots=roots, expected_lightgbm_version="4.5.0")
    source["samples"][0]["feature_vector"][0] += 0.01
    source["capture_sha256"] = hashlib.sha256(
        _canonical({key: value for key, value in source.items() if key != "capture_sha256"})
    ).hexdigest()
    source_path = tmp_path / "tampered.json"
    source_path.write_bytes(_canonical(source))

    with pytest.raises(MODULE.RuntimeParityError, match="normalized|SHA-256"):
        MODULE.replay(
            source_capture_path=source_path, registry_path=registry, artifact_path=artifact,
            expected_source_version="4.5.0", expected_lightgbm_version="4.5.0")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda vector: vector.pop(), "exactly 256"),
        (lambda vector: vector.__setitem__(0, 1.1), "invalid probability"),
        (lambda vector: vector.__setitem__(0, vector[0] + 0.01), "normalized"),
    ],
)
def test_replay_rejects_resealed_invalid_vector_shape_range_or_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
    message: str,
) -> None:
    registry, artifact, manifest, membership, roots = _fixture(tmp_path)

    class Booster:
        def __init__(self, *, model_str: str) -> None:
            assert model_str

        def predict(self, rows: list[list[float]]) -> list[float]:
            return [0.5]

    monkeypatch.setitem(sys.modules, "lightgbm", SimpleNamespace(Booster=Booster))
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda _: "4.5.0")
    source = MODULE.capture(
        registry_path=registry,
        artifact_path=artifact,
        sample_manifest_path=manifest,
        membership_path=membership,
        sample_roots=roots,
        expected_lightgbm_version="4.5.0",
    )
    mutation(source["samples"][0]["feature_vector"])
    unsigned = {key: value for key, value in source.items() if key != "capture_sha256"}
    source["capture_sha256"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    source_path = tmp_path / "invalid-vector.json"
    source_path.write_bytes(_canonical(source))

    with pytest.raises(MODULE.RuntimeParityError, match=message):
        MODULE.replay(
            source_capture_path=source_path,
            registry_path=registry,
            artifact_path=artifact,
            expected_source_version="4.5.0",
            expected_lightgbm_version="4.5.0",
        )


def test_replay_rejects_resealed_capture_with_different_provider_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, artifact, manifest, membership, roots = _fixture(tmp_path)

    class Booster:
        def __init__(self, *, model_str: str) -> None:
            assert model_str

        def predict(self, rows: list[list[float]]) -> list[float]:
            return [0.5]

    monkeypatch.setitem(sys.modules, "lightgbm", SimpleNamespace(Booster=Booster))
    monkeypatch.setattr(MODULE.importlib.metadata, "version", lambda _: "4.5.0")
    source = MODULE.capture(
        registry_path=registry,
        artifact_path=artifact,
        sample_manifest_path=manifest,
        membership_path=membership,
        sample_roots=roots,
        expected_lightgbm_version="4.5.0",
    )
    source["provider_registry_sha256"] = "f" * 64
    unsigned = {key: value for key, value in source.items() if key != "capture_sha256"}
    source["capture_sha256"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    source_path = tmp_path / "wrong-provider.json"
    source_path.write_bytes(_canonical(source))

    with pytest.raises(MODULE.RuntimeParityError, match="pinned provider"):
        MODULE.replay(
            source_capture_path=source_path,
            registry_path=registry,
            artifact_path=artifact,
            expected_source_version="4.5.0",
            expected_lightgbm_version="4.5.0",
        )
