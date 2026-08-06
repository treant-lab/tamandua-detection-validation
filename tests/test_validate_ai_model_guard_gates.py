from __future__ import annotations

import json
import subprocess
import sys
import hashlib
import importlib.util
import os
from pathlib import Path

from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
SCRIPT = ROOT / "scripts" / "validate_ai_model_guard_gates.py"
MANIFEST_SCRIPT = ROOT / "scripts" / "generate_ai_model_guard_manifest.py"
SCORECARD = REPO_ROOT / "docs" / "benchmarks" / "AI_MODEL_SCANNER_SCORECARD.md"
COVERAGE_PLAN = REPO_ROOT / "docs" / "ai-security" / "AI_MODEL_GUARD_BENCHMARK_MATRIX.md"
RESULTS = REPO_ROOT / "docs" / "benchmarks" / "AI_MODEL_SCANNER_VALIDATION_20260630T134213Z.json"
LATEST_RESULTS = REPO_ROOT / "docs" / "benchmarks" / "AI_MODEL_SCANNER_VALIDATION_20260714T182558Z.json"


def run_gate_subprocess() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scorecard",
            str(SCORECARD),
            "--coverage-plan",
            str(COVERAGE_PLAN),
            "--results",
            str(RESULTS),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_gate(*args: object) -> subprocess.CompletedProcess[str]:
    return run_cli_in_process(SCRIPT, [str(arg) for arg in args])


def run_manifest(*args: object) -> subprocess.CompletedProcess[str]:
    return run_cli_in_process(MANIFEST_SCRIPT, [str(arg) for arg in args])


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(tmp_path: Path, name: str, payload: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def write_manifest_fixture(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    sample_root = tmp_path / "samples"
    sample_root.mkdir()
    malicious = sample_root / "pickle_rce.pkl"
    benign = sample_root / "baseline_pickle.pkl"
    malicious.write_bytes(b"defanged pickle rce fixture")
    benign.write_bytes(b"benign pickle fixture")
    validation = write_json(
        tmp_path,
        "validation.json",
        {
            "corpus": {"malicious_count": 1, "clean_count": 1},
            "samples": [
                {
                    "name": "pickle_rce.pkl",
                    "type": "malicious",
                    "format": "pickle",
                    "attack": "Code execution via os.system",
                    "scanners": {"PickleGuard": {"flagged": True}},
                },
                {
                    "name": "baseline_pickle.pkl",
                    "type": "clean",
                    "format": "pickle",
                    "scanners": {"PickleGuard": {"flagged": False}},
                },
            ],
        },
    )
    hashes = {
        "pickle_rce.pkl": hashlib.sha256(malicious.read_bytes()).hexdigest(),
        "baseline_pickle.pkl": hashlib.sha256(benign.read_bytes()).hexdigest(),
    }
    completed = run_manifest("--validation-json", validation, "--sample-root", sample_root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    manifest = write_json(tmp_path, "manifest.json", json.loads(completed.stdout))
    return manifest, hashes


def test_ai_model_guard_current_scorecard_is_honest_blocked_gate() -> None:
    completed = run_gate_subprocess()

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["api_version"] == "tamandua.io/ai-model-guard-gate-report/v1"
    assert report["kind"] == "AiModelGuardGateReport"
    assert report["gate_status"] == "blocked_for_production_claim"
    assert report["external_claim_allowed"] is False
    assert report["local_gate_runnable"] is True
    assert report["claim_boundary"] == "small-corpus smoke/regression only"
    assert report["evidence"]["class"] == "smoke"
    assert report["sample_accounting"] == {
        "declared_benign": 3,
        "declared_malicious": 11,
        "observed_benign": 3,
        "observed_malicious": 11,
        "total_samples": 14,
    }
    assert report["outcomes"]["tp"] == 7
    assert report["outcomes"]["tn"] == 3
    assert report["outcomes"]["fp"] == 0
    assert report["outcomes"]["fn"] == 4
    assert report["known_signature_gate"]["passed"] is True
    assert report["known_signature_gate"]["misses"] == []
    assert "coverage_plan_minimums_not_met" in report["promotion_blockers"]
    assert "overall_benign_sample_count_below_300" in report["promotion_blockers"]
    assert "overall_adversarial_sample_count_below_150" in report["promotion_blockers"]
    assert report["coverage_plan"]["formats"]["pickle"]["benign"] == 1
    assert report["coverage_plan"]["formats"]["pickle"]["adversarial"] == 1
    assert report["coverage_plan"]["formats"]["gguf"]["benign_gap"] == 40


def test_ai_model_guard_gate_can_write_report(tmp_path: Path) -> None:
    output = tmp_path / "ai-model-guard-gate-report.json"

    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--results",
        RESULTS,
        "--output",
        output,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(completed.stdout)


def test_ai_model_guard_gate_defaults_to_latest_validation_json() -> None:
    latest_results = max(
        (REPO_ROOT / "docs" / "benchmarks").glob("AI_MODEL_SCANNER_VALIDATION_*.json"),
        key=lambda path: path.name,
    )

    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["evidence"]["source_kind"] == "validation_json"
    assert report["evidence"]["source_artifacts"][-1] == latest_results.relative_to(REPO_ROOT).as_posix()


def test_ai_model_guard_latest_validation_uses_filename_timestamp_not_mtime(tmp_path: Path) -> None:
    older = write_json(tmp_path, "AI_MODEL_SCANNER_VALIDATION_20260101T000000Z.json", {"samples": []})
    newer = write_json(tmp_path, "AI_MODEL_SCANNER_VALIDATION_20260201T000000Z.json", {"samples": []})
    os.utime(newer, (1, 1))
    os.utime(older, (2, 2))

    gate_module = load_module(SCRIPT, "ai_model_guard_gate_for_latest_test")
    manifest_module = load_module(MANIFEST_SCRIPT, "ai_model_guard_manifest_for_latest_test")

    assert gate_module.latest_validation_json(tmp_path) == newer.resolve()
    assert manifest_module.latest_validation_json(tmp_path) == newer


def test_ai_model_guard_gate_accepts_explicit_validation_json() -> None:
    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--validation-json",
        RESULTS,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["evidence"]["source_kind"] == "validation_json"
    assert report["evidence"]["source_artifacts"][-1] == "docs/benchmarks/AI_MODEL_SCANNER_VALIDATION_20260630T134213Z.json"


def test_ai_model_guard_manifest_generator_normalizes_samples(tmp_path: Path) -> None:
    manifest, hashes = write_manifest_fixture(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))

    assert payload["api_version"] == "tamandua.io/ai-model-guard-manifest/v1"
    assert payload["kind"] == "AiModelGuardManifest"
    assert payload["samples"] == [
        {
            "attack_family": "unsafe_deserialization",
            "format": "pickle",
            "label": "adversarial",
            "path": (tmp_path / "samples" / "pickle_rce.pkl").as_posix(),
            "sample_id": "pickle_rce.pkl",
            "sha256": hashes["pickle_rce.pkl"],
        },
        {
            "attack_family": None,
            "format": "pickle",
            "label": "benign",
            "path": (tmp_path / "samples" / "baseline_pickle.pkl").as_posix(),
            "sample_id": "baseline_pickle.pkl",
            "sha256": hashes["baseline_pickle.pkl"],
        },
    ]


def test_ai_model_guard_gate_accepts_manifest_input(tmp_path: Path) -> None:
    manifest, _hashes = write_manifest_fixture(tmp_path)

    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--manifest",
        manifest,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["evidence"]["source_kind"] == "manifest"
    assert report["sample_accounting"] == {
        "declared_benign": 1,
        "declared_malicious": 1,
        "observed_benign": 1,
        "observed_malicious": 1,
        "total_samples": 2,
    }
    assert report["outcomes"] == {
        "benign_total": 1,
        "fn": None,
        "fnr": None,
        "fp": None,
        "fpr": None,
        "malicious_total": 1,
        "tn": None,
        "tp": None,
    }
    assert "manifest_only_without_scanner_outcomes" in report["promotion_blockers"]


def test_ai_model_guard_manifest_input_does_not_count_embedded_scanner_outcomes(tmp_path: Path) -> None:
    manifest, _hashes = write_manifest_fixture(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["samples"][0]["scanners"] = {"PickleGuard": {"flagged": True}}
    payload["samples"][1]["scanners"] = {"PickleGuard": {"flagged": False}}
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--manifest",
        manifest,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["evidence"]["source_kind"] == "manifest"
    assert report["outcomes"]["tp"] is None
    assert report["outcomes"]["tn"] is None
    assert report["outcomes"]["fp"] is None
    assert report["outcomes"]["fn"] is None
    assert "manifest_only_without_scanner_outcomes" in report["promotion_blockers"]


def test_ai_model_guard_fail_on_blocked_returns_distinct_status() -> None:
    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--results",
        RESULTS,
        "--fail-on-blocked",
    )

    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["gate_status"] == "blocked_for_production_claim"


def test_ai_model_guard_gate_rejects_scorecard_without_claim_boundary(tmp_path: Path) -> None:
    scorecard = tmp_path / "scorecard.md"
    text = SCORECARD.read_text(encoding="utf-8").replace("not production-ready", "production-grade")
    scorecard.write_text(text, encoding="utf-8")

    completed = run_gate(
        "--scorecard",
        scorecard,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--results",
        RESULTS,
    )

    assert completed.returncode == 1
    assert "scorecard must preserve 'not production-ready' claim boundary" in completed.stdout


def test_ai_model_guard_gate_rejects_corpus_count_mismatch(tmp_path: Path) -> None:
    payload = json.loads(RESULTS.read_text(encoding="utf-8"))
    payload["corpus"]["clean_count"] = 99
    results = write_json(tmp_path, "results.json", payload)
    scorecard = tmp_path / "scorecard.md"
    scorecard.write_text(SCORECARD.read_text(encoding="utf-8").replace(str(RESULTS), str(results)), encoding="utf-8")

    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--results",
        results,
    )

    assert completed.returncode == 1
    assert "corpus.clean_count must equal observed clean samples" in completed.stdout


def test_ai_model_guard_gate_rejects_missing_coverage_plan_section(tmp_path: Path) -> None:
    plan = tmp_path / "plan.md"
    plan.write_text(
        COVERAGE_PLAN.read_text(encoding="utf-8").replace("## Promotion Rules", "## Promotion Notes"),
        encoding="utf-8",
    )

    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        plan,
        "--results",
        RESULTS,
    )

    assert completed.returncode == 1
    assert "missing required coverage-plan section '## Promotion Rules'" in completed.stdout


def test_ai_model_guard_gate_flags_known_signature_miss(tmp_path: Path) -> None:
    payload = json.loads(RESULTS.read_text(encoding="utf-8"))
    sample = next(item for item in payload["samples"] if item["name"] == "onnx_external_refs.onnx")
    sample["scanners"]["ONNXGuard"]["flagged"] = False
    results = write_json(tmp_path, "known-signature-miss.json", payload)

    completed = run_gate(
        "--scorecard",
        SCORECARD,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--results",
        results,
    )

    assert completed.returncode == 1
    assert "scorecard must reference source artifact" in completed.stdout

    scorecard = tmp_path / "scorecard.md"
    scorecard.write_text(
        SCORECARD.read_text(encoding="utf-8").replace(
            "docs/benchmarks/AI_MODEL_SCANNER_VALIDATION_20260630T134213Z.json",
            str(results.relative_to(REPO_ROOT)) if results.is_relative_to(REPO_ROOT) else results.as_posix(),
        ),
        encoding="utf-8",
    )
    completed = run_gate(
        "--scorecard",
        scorecard,
        "--coverage-plan",
        COVERAGE_PLAN,
        "--results",
        results,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["known_signature_gate"]["passed"] is False
    assert report["known_signature_gate"]["misses"] == [
        {
            "attack_family": "external_reference",
            "reason": "known signature sample was not flagged by any scanner",
            "sample_id": "onnx_external_refs.onnx",
        }
    ]
    assert "known_signature_fn" in report["promotion_blockers"]
