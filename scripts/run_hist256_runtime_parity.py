#!/usr/bin/env python3
"""Capture and compare non-decisional hist256 scores across pinned runtimes.

This is an endpoint-shadow runtime parity check.  It deliberately uses only
governed train members, never opens holdout data, and emits no efficacy metric
or verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import stat
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any


API_VERSION = "tamandua.io/hist256-runtime-parity/v1"
CAPTURE_VERSION = "tamandua.io/hist256-runtime-parity-capture/v2"
MANIFEST_VERSION = "tamandua.io/hist256-runtime-parity-samples/v1"
REGISTRY_VERSION = "tamandua.local_model_providers.v1"
FEATURE_CONTRACT_ID = "tamandua.byte-histogram-256.v1"
FEATURE_CONTRACT_SHA256 = "2395c70fcb3cad70e3b16d8ac10d095ed3d10c1905f57f778a842df4a83d5d29"
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_MEMBERSHIP_BYTES = 1_000_000_000
MAX_PARITY_SAMPLES = 32


class RuntimeParityError(ValueError):
    """A parity input or result cannot be trusted."""


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise RuntimeParityError(f"{field} must be a lowercase SHA-256")
    return value


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _guarded_bytes(path: Path, maximum: int) -> tuple[bytes, str]:
    path = path.absolute()
    before = path.lstat()
    attributes = getattr(before, "st_file_attributes", 0)
    reparse = attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or reparse
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise RuntimeParityError(f"{path.name} is not a bounded single-link plain file")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        while total <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.stat()
    if len({_identity(item) for item in (before, opened, after, current)}) != 1:
        raise RuntimeParityError(f"{path.name} changed during guarded read")
    if total != before.st_size or total > maximum:
        raise RuntimeParityError(f"{path.name} exceeded its guarded bound")
    return b"".join(chunks), digest.hexdigest()


def _load_json(path: Path, maximum: int) -> tuple[dict[str, Any], str]:
    raw, digest = _guarded_bytes(path, maximum)
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeParityError(f"{path.name} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeParityError(f"{path.name} must contain a JSON object")
    return value, digest


def _parse_roots(values: list[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise RuntimeParityError("sample roots must use ID=ABSOLUTE_PATH")
        root_id, raw_path = value.split("=", 1)
        if not root_id or root_id in roots:
            raise RuntimeParityError("sample root identifiers must be unique and non-empty")
        path = Path(raw_path).absolute()
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeParityError(f"sample root {root_id} is not a plain directory")
        roots[root_id] = path
    return roots


def _provider(registry_path: Path, artifact_path: Path) -> tuple[dict[str, Any], str, bytes]:
    registry, registry_sha = _load_json(registry_path, MAX_CONFIG_BYTES)
    if registry.get("schema_version") != REGISTRY_VERSION:
        raise RuntimeParityError("provider registry schema is incompatible")
    policy = registry.get("policy")
    if not isinstance(policy, dict) or any(
        policy.get(field) is not False
        for field in (
            "enabled_default",
            "remote_bind_allowed",
            "remote_download_allowed",
            "enforcement_allowed",
        )
    ):
        raise RuntimeParityError("provider registry is not fail-closed")
    providers = registry.get("providers")
    if not isinstance(providers, list) or len(providers) != 1 or not isinstance(providers[0], dict):
        raise RuntimeParityError("provider registry must contain exactly one candidate")
    candidate = providers[0]
    expected = {
        "implementation": "lightgbm_local",
        "enabled": False,
        "evidence_class": "bootstrap_shadow_calibration",
        "decision_mode": "endpoint_shadow",
        "feature_contract_id": FEATURE_CONTRACT_ID,
        "feature_dimension": 256,
        "score_orientation": "higher_is_more_malicious",
    }
    if any(candidate.get(key) != value for key, value in expected.items()):
        raise RuntimeParityError("candidate is not the pinned default-off hist256 shadow provider")
    artifact_raw, artifact_sha = _guarded_bytes(
        artifact_path, int(candidate.get("artifact_size_bytes", 0))
    )
    if len(artifact_raw) != candidate.get("artifact_size_bytes"):
        raise RuntimeParityError("artifact size does not match provider pin")
    if artifact_sha != candidate.get("artifact_sha256"):
        raise RuntimeParityError("artifact SHA-256 does not match provider pin")
    return candidate, registry_sha, artifact_raw


def _membership(path: Path, expected_sha: str) -> dict[str, int]:
    raw, observed_sha = _guarded_bytes(path, MAX_MEMBERSHIP_BYTES)
    if observed_sha != expected_sha:
        raise RuntimeParityError("training membership SHA-256 does not match sample manifest")
    result: dict[str, int] = {}
    previous = ""
    for number, line in enumerate(raw.splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeParityError(f"membership line {number} is invalid") from exc
        if not isinstance(value, dict) or set(value) != {"label", "sha256"}:
            raise RuntimeParityError(f"membership line {number} has an invalid shape")
        digest = _require_sha256(value["sha256"], f"membership line {number}")
        label = value["label"]
        if label not in (0, 1) or isinstance(label, bool) or digest <= previous:
            raise RuntimeParityError("training membership is not canonical and ordered")
        result[digest] = label
        previous = digest
    return result


def _features(content: bytes) -> list[float]:
    counts = [0] * 256
    for value in content:
        counts[value] += 1
    denominator = max(len(content), 1)
    return [count / denominator for count in counts]


def _feature_sha(features: list[float]) -> str:
    return _sha256(struct.pack("!256d", *features))


def _validated_feature_vector(value: Any, expected_sha: Any) -> list[float]:
    expected_digest = _require_sha256(expected_sha, "feature_vector_sha256")
    if not isinstance(value, list) or len(value) != 256:
        raise RuntimeParityError("sealed feature vector must contain exactly 256 values")
    features: list[float] = []
    for item in value:
        if isinstance(item, (bool, str, bytes, dict, list)):
            raise RuntimeParityError("sealed feature vector contains a non-numeric value")
        feature = float(item)
        if not math.isfinite(feature) or feature < 0.0 or feature > 1.0:
            raise RuntimeParityError("sealed feature vector contains an invalid probability")
        features.append(feature)
    if not math.isclose(sum(features), 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise RuntimeParityError("sealed feature vector is not normalized")
    if _feature_sha(features) != expected_digest:
        raise RuntimeParityError("sealed feature vector SHA-256 mismatch")
    return features


def _single_score(raw: Any) -> float:
    value = raw.tolist() if callable(getattr(raw, "tolist", None)) else raw
    while isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise RuntimeParityError("LightGBM returned a non-scalar prediction")
        value = value[0]
    if isinstance(value, (bool, str, bytes, dict)):
        raise RuntimeParityError("LightGBM returned a non-numeric prediction")
    score = float(value)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise RuntimeParityError("LightGBM returned a non-probability score")
    return score


def capture(
    *,
    registry_path: Path,
    artifact_path: Path,
    sample_manifest_path: Path,
    membership_path: Path,
    sample_roots: list[str],
    expected_lightgbm_version: str,
) -> dict[str, Any]:
    candidate, registry_sha, artifact_raw = _provider(registry_path, artifact_path)
    manifest, manifest_sha = _load_json(sample_manifest_path, MAX_CONFIG_BYTES)
    if manifest.get("api_version") != MANIFEST_VERSION:
        raise RuntimeParityError("sample manifest API is incompatible")
    if (
        manifest.get("evidence_class") != "runtime_parity_smoke"
        or manifest.get("used_split") != "train"
        or manifest.get("holdout_opened") is not False
        or manifest.get("efficacy_claim_allowed") is not False
    ):
        raise RuntimeParityError("sample manifest does not preserve the parity-only claim boundary")
    membership_sha = _require_sha256(
        manifest.get("training_membership_sha256"), "training_membership_sha256"
    )
    members = _membership(membership_path, membership_sha)
    samples = manifest.get("samples")
    if not isinstance(samples, list) or not 2 <= len(samples) <= MAX_PARITY_SAMPLES:
        raise RuntimeParityError("sample manifest must contain a small bounded sample set")
    roots = _parse_roots(sample_roots)
    prepared: list[tuple[str, int, bytes, list[float]]] = []
    seen: set[str] = set()
    labels_seen: set[int] = set()
    for item in samples:
        if not isinstance(item, dict) or set(item) != {"sha256", "label", "root_id"}:
            raise RuntimeParityError("sample entries must contain only sha256, label, and root_id")
        digest = _require_sha256(item["sha256"], "sample.sha256")
        label = item["label"]
        root_id = item["root_id"]
        if digest in seen or label not in (0, 1) or isinstance(label, bool):
            raise RuntimeParityError("sample entries must be unique and use labels 0/1")
        if members.get(digest) != label:
            raise RuntimeParityError("sample is not an exact member of the pinned train split")
        if root_id not in roots:
            raise RuntimeParityError("sample references an unavailable governed root")
        content, observed = _guarded_bytes(
            roots[root_id] / f"{digest}.bin", int(candidate.get("max_file_bytes", 0))
        )
        if observed != digest:
            raise RuntimeParityError("sample body SHA-256 does not match its governed identity")
        prepared.append((digest, label, content, _features(content)))
        seen.add(digest)
        labels_seen.add(label)
    if labels_seen != {0, 1}:
        raise RuntimeParityError("parity samples must include governed goodware and Maki malware")
    installed = importlib.metadata.version("lightgbm")
    if installed != expected_lightgbm_version:
        raise RuntimeParityError(
            f"installed LightGBM {installed} differs from expected {expected_lightgbm_version}"
        )
    try:
        import lightgbm as lgb  # type: ignore

        booster = lgb.Booster(model_str=artifact_raw.decode("ascii"))
    except Exception as exc:
        raise RuntimeParityError("pinned LightGBM artifact could not be loaded") from exc
    observations = []
    for digest, label, content, feature_vector in prepared:
        observations.append(
            {
                "sha256": digest,
                "label": label,
                "size_bytes": len(content),
                "feature_vector": feature_vector,
                "feature_vector_sha256": _feature_sha(feature_vector),
                "score": _single_score(booster.predict([feature_vector])),
            }
        )
    result = {
        "api_version": CAPTURE_VERSION,
        "evidence_class": "runtime_parity_smoke",
        "artifact_sha256": candidate["artifact_sha256"],
        "provider_registry_sha256": registry_sha,
        "sample_manifest_sha256": manifest_sha,
        "training_membership_sha256": membership_sha,
        "feature_contract_id": FEATURE_CONTRACT_ID,
        "feature_contract_sha256": FEATURE_CONTRACT_SHA256,
        "model_contract_id": candidate["model_contract_id"],
        "runtime": {
            "lightgbm_version": installed,
            "python_version": platform.python_version(),
            "platform": platform.system().lower(),
        },
        "samples": observations,
        "holdout_opened": False,
        "efficacy_claim_allowed": False,
        "enforcement_allowed": False,
        "claim_boundary": "Pinned train-sample runtime parity only; no efficacy, verdict, promotion, deployment, or enforcement claim.",
    }
    result["capture_sha256"] = _sha256(_canonical(result))
    return result


def _verify_capture(value: dict[str, Any]) -> None:
    seal = value.get("capture_sha256")
    unsigned = dict(value)
    unsigned.pop("capture_sha256", None)
    if seal != _sha256(_canonical(unsigned)):
        raise RuntimeParityError("runtime capture seal is invalid")
    if (
        value.get("api_version") != CAPTURE_VERSION
        or value.get("evidence_class") != "runtime_parity_smoke"
        or value.get("holdout_opened") is not False
        or value.get("efficacy_claim_allowed") is not False
        or value.get("enforcement_allowed") is not False
    ):
        raise RuntimeParityError("runtime capture escaped the parity-only claim boundary")
    _require_sha256(value.get("artifact_sha256"), "artifact_sha256")
    _require_sha256(value.get("provider_registry_sha256"), "provider_registry_sha256")
    _require_sha256(value.get("sample_manifest_sha256"), "sample_manifest_sha256")
    _require_sha256(value.get("training_membership_sha256"), "training_membership_sha256")
    if (
        value.get("feature_contract_id") != FEATURE_CONTRACT_ID
        or value.get("feature_contract_sha256") != FEATURE_CONTRACT_SHA256
    ):
        raise RuntimeParityError("runtime capture feature contract is incompatible")
    samples = value.get("samples")
    if not isinstance(samples, list) or not 2 <= len(samples) <= MAX_PARITY_SAMPLES:
        raise RuntimeParityError("runtime capture has no bounded sealed feature vectors")
    seen: set[str] = set()
    for item in samples:
        if not isinstance(item, dict):
            raise RuntimeParityError("runtime capture sample is malformed")
        digest = _require_sha256(item.get("sha256"), "sample.sha256")
        if digest in seen:
            raise RuntimeParityError("runtime capture samples are not unique")
        _validated_feature_vector(item.get("feature_vector"), item.get("feature_vector_sha256"))
        _single_score(item.get("score"))
        seen.add(digest)


def replay(
    *,
    source_capture_path: Path,
    registry_path: Path,
    artifact_path: Path,
    expected_source_version: str,
    expected_lightgbm_version: str,
) -> dict[str, Any]:
    """Score a sealed hist256 capture without reopening any raw sample body."""
    source, source_sha = _load_json(source_capture_path, MAX_CONFIG_BYTES)
    _verify_capture(source)
    if source.get("runtime", {}).get("lightgbm_version") != expected_source_version:
        raise RuntimeParityError("source capture runtime does not match the explicit version pin")
    candidate, registry_sha, artifact_raw = _provider(registry_path, artifact_path)
    expected_metadata = {
        "artifact_sha256": candidate["artifact_sha256"],
        "provider_registry_sha256": registry_sha,
        "feature_contract_id": FEATURE_CONTRACT_ID,
        "feature_contract_sha256": FEATURE_CONTRACT_SHA256,
        "model_contract_id": candidate["model_contract_id"],
    }
    if any(source.get(key) != value for key, value in expected_metadata.items()):
        raise RuntimeParityError("source capture does not match the pinned provider")
    installed = importlib.metadata.version("lightgbm")
    if installed != expected_lightgbm_version:
        raise RuntimeParityError(
            f"installed LightGBM {installed} differs from expected {expected_lightgbm_version}"
        )
    try:
        import lightgbm as lgb  # type: ignore

        booster = lgb.Booster(model_str=artifact_raw.decode("ascii"))
    except Exception as exc:
        raise RuntimeParityError("pinned LightGBM artifact could not be loaded") from exc
    samples = []
    for item in source["samples"]:
        features = _validated_feature_vector(
            item.get("feature_vector"), item.get("feature_vector_sha256")
        )
        samples.append(
            {
                "sha256": item["sha256"],
                "label": item["label"],
                "size_bytes": item["size_bytes"],
                "feature_vector": features,
                "feature_vector_sha256": item["feature_vector_sha256"],
                "score": _single_score(booster.predict([features])),
            }
        )
    result = {
        key: source[key]
        for key in (
            "api_version",
            "evidence_class",
            "artifact_sha256",
            "provider_registry_sha256",
            "sample_manifest_sha256",
            "training_membership_sha256",
            "feature_contract_id",
            "feature_contract_sha256",
            "model_contract_id",
            "holdout_opened",
            "efficacy_claim_allowed",
            "enforcement_allowed",
            "claim_boundary",
        )
    }
    result.update(
        {
            "runtime": {
                "lightgbm_version": installed,
                "python_version": platform.python_version(),
                "platform": platform.system().lower(),
            },
            "samples": samples,
            "source_capture_sha256": source_sha,
        }
    )
    result["capture_sha256"] = _sha256(_canonical(result))
    return result


def compare(
    *, left_path: Path, right_path: Path, expected_versions: tuple[str, str], max_delta: float
) -> dict[str, Any]:
    if not math.isfinite(max_delta) or max_delta < 0:
        raise RuntimeParityError("max score delta must be finite and non-negative")
    left, left_sha = _load_json(left_path, MAX_CONFIG_BYTES)
    right, right_sha = _load_json(right_path, MAX_CONFIG_BYTES)
    _verify_capture(left)
    _verify_capture(right)
    for field in (
        "artifact_sha256",
        "provider_registry_sha256",
        "sample_manifest_sha256",
        "training_membership_sha256",
        "feature_contract_id",
        "feature_contract_sha256",
        "model_contract_id",
    ):
        if left.get(field) != right.get(field):
            raise RuntimeParityError(f"runtime captures disagree on {field}")
    observed_versions = (
        left.get("runtime", {}).get("lightgbm_version"),
        right.get("runtime", {}).get("lightgbm_version"),
    )
    if observed_versions != expected_versions:
        raise RuntimeParityError("runtime versions do not match the explicit comparison pin")
    left_samples = left.get("samples")
    right_samples = right.get("samples")
    if not isinstance(left_samples, list) or not isinstance(right_samples, list):
        raise RuntimeParityError("runtime captures have no bounded sample observations")
    left_by_sha = {item.get("sha256"): item for item in left_samples if isinstance(item, dict)}
    right_by_sha = {item.get("sha256"): item for item in right_samples if isinstance(item, dict)}
    if len(left_by_sha) != len(left_samples) or set(left_by_sha) != set(right_by_sha):
        raise RuntimeParityError("runtime captures do not contain the same unique samples")
    deltas: list[dict[str, Any]] = []
    for digest in sorted(left_by_sha):
        left_item, right_item = left_by_sha[digest], right_by_sha[digest]
        for field in ("label", "size_bytes", "feature_vector_sha256"):
            if left_item.get(field) != right_item.get(field):
                raise RuntimeParityError(f"runtime captures disagree on sample {field}")
        delta = abs(float(left_item["score"]) - float(right_item["score"]))
        if not math.isfinite(delta) or delta > max_delta:
            raise RuntimeParityError(f"score parity delta exceeds {max_delta}")
        deltas.append({"sha256": digest, "absolute_score_delta": delta})
    evidence = {
        "api_version": API_VERSION,
        "status": "passed",
        "evidence_class": "runtime_parity_smoke",
        "captures": [
            {"sha256": left_sha, "runtime": left["runtime"]},
            {"sha256": right_sha, "runtime": right["runtime"]},
        ],
        "artifact_sha256": left["artifact_sha256"],
        "model_contract_id": left["model_contract_id"],
        "feature_contract_id": left["feature_contract_id"],
        "feature_contract_sha256": left["feature_contract_sha256"],
        "sample_manifest_sha256": left["sample_manifest_sha256"],
        "training_membership_sha256": left["training_membership_sha256"],
        "sample_count": len(deltas),
        "max_allowed_absolute_score_delta": max_delta,
        "max_observed_absolute_score_delta": max(
            (item["absolute_score_delta"] for item in deltas), default=0.0
        ),
        "sample_deltas": deltas,
        "holdout_opened": False,
        "efficacy_claim_allowed": False,
        "promotion_eligible": False,
        "enforcement_allowed": False,
        "claim_boundary": "Cross-version endpoint-shadow score parity on pinned train samples only; no efficacy, verdict, promotion, deployment, or enforcement claim.",
    }
    evidence["evidence_sha256"] = _sha256(_canonical(evidence))
    return evidence


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise RuntimeParityError(f"refusing to overwrite {path.name}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        raw = _canonical(value)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--candidate-registry", required=True, type=Path)
    capture_parser.add_argument("--artifact", required=True, type=Path)
    capture_parser.add_argument("--sample-manifest", required=True, type=Path)
    capture_parser.add_argument("--training-membership", required=True, type=Path)
    capture_parser.add_argument("--sample-root", action="append", default=[])
    capture_parser.add_argument("--expected-lightgbm-version", required=True)
    capture_parser.add_argument("--output", required=True, type=Path)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--source-capture", required=True, type=Path)
    replay_parser.add_argument("--candidate-registry", required=True, type=Path)
    replay_parser.add_argument("--artifact", required=True, type=Path)
    replay_parser.add_argument("--expected-source-version", required=True)
    replay_parser.add_argument("--expected-lightgbm-version", required=True)
    replay_parser.add_argument("--output", required=True, type=Path)
    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--left", required=True, type=Path)
    compare_parser.add_argument("--right", required=True, type=Path)
    compare_parser.add_argument("--expected-left-version", required=True)
    compare_parser.add_argument("--expected-right-version", required=True)
    compare_parser.add_argument("--max-absolute-score-delta", type=float, default=1e-12)
    compare_parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute-runtime-parity", action="store_true")
    args = parser.parse_args()
    try:
        if not args.execute_runtime_parity:
            raise RuntimeParityError("explicit --execute-runtime-parity opt-in is required")
        if args.command == "capture":
            result = capture(
                registry_path=args.candidate_registry,
                artifact_path=args.artifact,
                sample_manifest_path=args.sample_manifest,
                membership_path=args.training_membership,
                sample_roots=args.sample_root,
                expected_lightgbm_version=args.expected_lightgbm_version,
            )
        elif args.command == "replay":
            result = replay(
                source_capture_path=args.source_capture,
                registry_path=args.candidate_registry,
                artifact_path=args.artifact,
                expected_source_version=args.expected_source_version,
                expected_lightgbm_version=args.expected_lightgbm_version,
            )
        else:
            result = compare(
                left_path=args.left,
                right_path=args.right,
                expected_versions=(args.expected_left_version, args.expected_right_version),
                max_delta=args.max_absolute_score_delta,
            )
        _write_new(args.output, result)
    except (OSError, RuntimeParityError, importlib.metadata.PackageNotFoundError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"status": "passed", "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
