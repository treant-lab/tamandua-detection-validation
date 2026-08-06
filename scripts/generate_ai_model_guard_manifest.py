#!/usr/bin/env python3
"""Build an offline AI Model Guard corpus manifest from validation samples."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    is_standalone = lambda: False

REPO_ROOT = ROOT.parent.parent if is_standalone() else ROOT
DEFAULT_SAMPLE_ROOTS = [
    REPO_ROOT / "apps" / "tamandua_ml" / "samples" / "malicious",
    REPO_ROOT / "apps" / "tamandua_ml" / "samples" / "clean",
]
DEFAULT_VALIDATION_GLOB = "AI_MODEL_SCANNER_VALIDATION_*.json"
DEFAULT_VALIDATION_DIR = REPO_ROOT / "docs" / "benchmarks"
API_VERSION = "tamandua.io/ai-model-guard-manifest/v1"
KIND = "AiModelGuardManifest"
VALIDATION_NAME_PATTERN = re.compile(r"^AI_MODEL_SCANNER_VALIDATION_(?P<stamp>\d{8}T\d{6}Z)\.json$")
ATTACK_FAMILY_PATTERNS = {
    "format_confusion": re.compile(r"format confusion|disguised", re.I),
    "unsafe_deserialization": re.compile(r"(code execution|os\.system|pickle)", re.I),
    "template_code_execution": re.compile(r"(cve-2024-34359|jinja)", re.I),
    "external_reference": re.compile(r"external data|external ref|path traversal", re.I),
    "parser_dos": re.compile(r"dos|compression|truncated|bomb|size mismatch", re.I),
    "prompt_injection": re.compile(r"prompt|jailbreak", re.I),
    "weight_anomaly": re.compile(r"anomalous|weight|lsb|steganography|extra keys|lora|adapter", re.I),
    "config_injection": re.compile(r"config", re.I),
}


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def validation_sort_key(path: Path) -> tuple[str, str]:
    match = VALIDATION_NAME_PATTERN.match(path.name)
    stamp = match.group("stamp") if match else ""
    return stamp, path.name


def latest_validation_json(directory: Path = DEFAULT_VALIDATION_DIR) -> Path:
    candidates = sorted(directory.glob(DEFAULT_VALIDATION_GLOB), key=validation_sort_key, reverse=True)
    if not candidates:
        raise FileNotFoundError(f"{repo_rel(directory)}: no {DEFAULT_VALIDATION_GLOB} files found")
    return candidates[0]


def sample_id_for(name: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip().replace("\\", "/")).strip("-")
    if not normalized:
        raise ValueError("sample name cannot normalize to an empty sample_id")
    return normalized


def label_for(sample_type: str) -> str:
    if sample_type == "clean":
        return "benign"
    if sample_type == "malicious":
        return "adversarial"
    raise ValueError(f"unsupported sample type {sample_type!r}")


def attack_family_for(sample: dict[str, Any]) -> str | None:
    if sample.get("type") == "clean" or sample.get("label") == "benign":
        return None
    if isinstance(sample.get("attack_family"), str):
        return str(sample["attack_family"])
    attack_text = f"{sample.get('attack', '')} {sample.get('name', '')}"
    for family, pattern in ATTACK_FAMILY_PATTERNS.items():
        if pattern.search(attack_text):
            return family
    return None


def find_sample_path(sample_name: str, sample_roots: list[Path]) -> Path:
    normalized = sample_name.replace("\\", "/").lstrip("/")
    matches: list[Path] = []
    for root in sample_roots:
        candidate = (root / normalized).resolve()
        if candidate.is_file():
            matches.append(candidate)
            continue
        basename = Path(normalized).name
        matches.extend(path.resolve() for path in root.rglob(basename) if path.is_file())

    unique = sorted(set(matches), key=lambda path: path.as_posix())
    if not unique:
        roots = ", ".join(repo_rel(root) for root in sample_roots)
        raise FileNotFoundError(f"{sample_name}: sample file not found under {roots}")
    if len(unique) > 1:
        rendered = ", ".join(repo_rel(path) for path in unique)
        raise ValueError(f"{sample_name}: ambiguous sample path matches: {rendered}")
    return unique[0]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(validation_json: Path, sample_roots: list[Path]) -> dict[str, Any]:
    payload = load_json(validation_json)
    samples = payload.get("samples")
    if not isinstance(samples, list) or not all(isinstance(sample, dict) for sample in samples):
        raise ValueError(f"{repo_rel(validation_json)}: samples must be a list of objects")

    manifest_samples: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sample in samples:
        name = sample.get("name")
        fmt = sample.get("format")
        sample_type = sample.get("type")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{repo_rel(validation_json)}: sample.name must be a non-empty string")
        if not isinstance(fmt, str) or not fmt:
            raise ValueError(f"{name}: sample.format must be a non-empty string")
        if not isinstance(sample_type, str):
            raise ValueError(f"{name}: sample.type must be a string")

        sample_id = sample_id_for(name)
        if sample_id in seen:
            raise ValueError(f"{name}: duplicate sample_id {sample_id!r}")
        seen.add(sample_id)

        path = find_sample_path(name, sample_roots)
        manifest_samples.append(
            {
                "sample_id": sample_id,
                "format": fmt.lower(),
                "label": label_for(sample_type),
                "attack_family": attack_family_for(sample),
                "sha256": sha256_file(path),
                "path": repo_rel(path),
            }
        )

    return {
        "api_version": API_VERSION,
        "kind": KIND,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_validation_json": repo_rel(validation_json),
        "sample_roots": [repo_rel(root) for root in sample_roots],
        "samples": manifest_samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation-json", type=Path, default=None)
    parser.add_argument("--sample-root", type=Path, action="append", default=None)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    validation_json = args.validation_json.resolve() if args.validation_json else latest_validation_json().resolve()
    sample_roots = [path.resolve() for path in (args.sample_root or DEFAULT_SAMPLE_ROOTS)]

    try:
        manifest = build_manifest(validation_json, sample_roots)
    except (OSError, ValueError) as exc:
        print(str(exc))
        return 1

    rendered = json.dumps(manifest, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
