#!/usr/bin/env python3
"""Fail-closed source contract for the licensed hosted Unity native smoke."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import re

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = pathlib.Path(".github/workflows/anti-cheat-unity-hosted-smoke.yml")
HARNESS = pathlib.Path("sdk/game/unity/scripts/run_unity_native_smoke.ps1")
SCHEMA = pathlib.Path("schemas/anti_cheat_unity_native_smoke_attempt_v1.schema.json")
BENCHMARK_AUTHORITY = pathlib.Path("sdk/game/unity/TestProject/Assets/Editor/TamanduaBenchmarkBuild.cs")
NATIVE_ADAPTER = pathlib.Path("sdk/game/unity/Packages/io.tamandua.game-runtime/Runtime/TamanduaGameNative.cs")

CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
FALSE_CLAIMS = {
    "runtime_claimable": False,
    "performance_claimable": False,
    "product_ready": False,
    "production_ready": False,
    "parity_claimable": False,
    "external_claim_allowed": False,
    "independently_validated": False,
}


def parsed_yaml(source: str) -> dict:
    value = yaml.safe_load(source)
    if not isinstance(value, dict):
        return {}
    if True in value:
        if "on" in value:
            return {}
        value["on"] = value.pop(True)
    return value


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def valid_receipt() -> dict:
    digest = "a" * 64
    return {
        "schema_version": "tamandua.anti_cheat.unity_native_smoke_attempt/v1",
        "evidence_class": "hosted_licensed_unity_native_smoke_attempt",
        "state": "completed",
        "stage": "complete",
        "attempt": {
            "run_id": "1", "run_attempt": "1", "source_sha": "b" * 40,
            "workflow_sha": "b" * 40, "unity_version": "6000.3.16f1",
            "runner_os": "Windows", "runner_architecture": "x86_64",
            "run_root_id": f"unity-native-1-1-{'b' * 40}",
        },
        "hashes": {key: digest for key in (
            "cargo_lock_sha256", "runtime_source_sha256", "c_header_sha256",
            "adapter_source_sha256", "benchmark_authority_source_sha256",
            "trace_writer_source_sha256", "native_plugin_sha256", "player_sha256",
            "player_manifest_sha256", "benchmark_sha256", "benchmark_trace_sha256",
        )},
        "tests": {"expected_total": 18, "editmode": 18, "playmode": 0, "total": 18},
        "benchmark": {
            "warmup_frames": 2000, "sample_frames": 30000,
            "frame_delta_ms": {"p50": 1.0, "p95": 2.0, "p99": 3.0},
            "adapter_enqueue_us": {"p50": 1.0, "p95": 2.0, "p99": 3.0},
            "drops": 0, "crashes": 0, "peak_rss_bytes": 1,
        },
        "logs": [], "failure": None, "claims": dict(FALSE_CLAIMS),
    }


def receipt_problems(receipt: object, schema: dict) -> list[str]:
    problems: list[str] = []
    try:
        jsonschema.Draft202012Validator(schema).validate(receipt)
    except jsonschema.ValidationError:
        return ["receipt:schema"]
    if not isinstance(receipt, dict):
        return ["receipt:type"]
    if receipt.get("claims") != FALSE_CLAIMS:
        problems.append("receipt:claims")
    if receipt.get("state") == "completed":
        tests = mapping(receipt.get("tests"))
        counts = [tests.get(name) for name in ("editmode", "playmode", "total", "expected_total")]
        if any(isinstance(value, bool) or not isinstance(value, int) for value in counts):
            problems.append("receipt:tests:type")
        elif tests["editmode"] + tests["playmode"] != tests["total"] or tests["total"] != tests["expected_total"] or tests["expected_total"] != 18:
            problems.append("receipt:tests:relationship")
    benchmark = receipt.get("benchmark")
    if isinstance(benchmark, dict):
        for field in ("frame_delta_ms", "adapter_enqueue_us"):
            values = mapping(benchmark.get(field))
            percentiles = [values.get(key) for key in ("p50", "p95", "p99")]
            if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in percentiles):
                problems.append(f"receipt:percentiles:type:{field}")
            elif not (0 <= percentiles[0] <= percentiles[1] <= percentiles[2]):
                problems.append(f"receipt:percentiles:{field}")
    return problems


def strict_json(path: pathlib.Path) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    return json.loads(
        path.read_text(encoding="utf-8-sig"),
        object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite number: {value}")),
    )


def validate(root: pathlib.Path = ROOT) -> list[str]:
    problems: list[str] = []
    paths = [root / WORKFLOW, root / HARNESS, root / SCHEMA, root / BENCHMARK_AUTHORITY, root / NATIVE_ADAPTER]
    for path in paths:
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(root).as_posix()}")
    if problems:
        return problems

    workflow_source = (root / WORKFLOW).read_text(encoding="utf-8")
    harness = (root / HARNESS).read_text(encoding="utf-8")
    try:
        schema = json.loads((root / SCHEMA).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
    except (json.JSONDecodeError, jsonschema.SchemaError):
        problems.append("schema:invalid")
        return problems

    workflow = parsed_yaml(workflow_source)
    if set(workflow) != {"name", "on", "permissions", "concurrency", "jobs"}:
        problems.append("workflow:root_shape")
    dispatch = mapping(mapping(workflow.get("on")).get("workflow_dispatch"))
    if set(mapping(dispatch.get("inputs"))) != {"source_sha"}:
        problems.append("workflow:not_dispatch_only")
    if workflow.get("permissions") != {"contents": "read"}:
        problems.append("workflow:permissions")
    jobs = mapping(workflow.get("jobs"))
    if set(jobs) != {"unity-native-smoke"}:
        problems.append("workflow:jobs")
        return problems
    job = mapping(jobs["unity-native-smoke"])
    if job.get("runs-on") != ["self-hosted", "Windows", "X64", "tamandua-unity-6000-3-16f1"] or job.get("timeout-minutes") != 90:
        problems.append("workflow:runner")
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    by_id = {step.get("id"): step for step in steps if isinstance(step, dict) and step.get("id")}
    if set(by_id) != {"attempt", "input", "checkout", "harness"}:
        problems.append("workflow:step_ids")
    checkout = mapping(by_id.get("checkout"))
    checkout_with = mapping(checkout.get("with"))
    if checkout.get("uses") != CHECKOUT or checkout_with != {"ref": "${{ inputs.source_sha }}", "persist-credentials": False, "clean": True}:
        problems.append("workflow:checkout")
    upload = [step for step in steps if isinstance(step, dict) and step.get("uses") == UPLOAD]
    if len(upload) != 1 or upload[0].get("if") != "always()":
        problems.append("workflow:upload")
    finalize = [step for step in steps if isinstance(step, dict) and step.get("name") == "Finalize attempt on every terminal path"]
    if len(finalize) != 1 or finalize[0].get("if") != "always()":
        problems.append("workflow:finalize")

    workflow_tokens = (
        "if ($env:WORKFLOW_SHA -ne $env:SOURCE_SHA)",
        "licensed runner must provide UNITY_EDITOR_PATH",
        "unity-native-$($env:TMD_RUN_ID)-$($env:TMD_RUN_ATTEMPT)-$source",
        "runtime_claimable=$false",
        "performance_claimable=$false",
        "if ($receipt.state -eq 'attempt_started')",
        "elseif ($receipt.state -ne 'completed' -and $receipt.state -ne 'failed')",
        "./sdk/game/unity/scripts/run_unity_native_smoke.ps1",
        "retention-days: 7",
        "benchmark_authority_source_sha256=$null",
        "trace_writer_source_sha256=$null",
    )
    for token in workflow_tokens:
        if token not in workflow_source:
            problems.append(f"workflow:token:{token}")
    lowered_workflow = workflow_source.lower()
    for forbidden in ("pull_request:", "push:", "schedule:", "secrets.", "write-all", "-latest"):
        if forbidden in lowered_workflow:
            problems.append(f"workflow:forbidden:{forbidden}")

    harness_tokens = (
        "git -C $Root rev-parse HEAD",
        "git -C $Root rev-parse --show-toplevel",
        "(Join-Path $PSScriptRoot '../../../..')",
        "$ExpectedUnityVersion = '6000.3.16f1'",
        "$ExpectedTestTotal = 18",
        "$WarmupFrames = 2000",
        "$SampleFrames = 30000",
        "$MaxLogBytes = 65536",
        "$MaxLogRecords = 12",
        "--locked','--offline','--release','--target','x86_64-pc-windows-msvc",
        "tamandua_game_runtime_core.dll",
        "0x8664",
        "native plugin export set mismatch",
        "plugin export function/name count mismatch",
        "$functionCount = [BitConverter]::ToUInt32($bytes, $exportOffset + 20)",
        "plugin export ordinal coverage mismatch",
        "plugin forwarded export rejected",
        "'-testPlatform','EditMode'",
        "'-testPlatform','PlayMode'",
        "'-buildWindows64Player'",
        "BuildAndRunNativeBenchmark",
        "'-executeMethod'",
        "--tamandua-benchmark-output",
        "--tamandua-benchmark-trace",
        "trace_missing",
        "trace_writer_missing",
        "benchmark_receipt_missing",
        "player_manifest_sha256",
        "benchmark_trace_sha256",
        "benchmark_authority_source_sha256",
        "trace_writer_source_sha256",
        "completed receipt validation precedes atomic publication",
        "$members = @(Get-ChildItem -LiteralPath $root -Recurse -Force)",
        "player manifest path escaped or duplicated",
        "[IO.File]::Move($CandidateReceiptPath, $ReceiptPath, $true)",
        "$CandidateReceiptPath = Join-Path $env:RUNNER_TEMP",
        "--receipt",
        "contract_failed",
        "cargo_lock_sha256",
        "native_plugin_sha256",
        "player_sha256",
        "benchmark_sha256",
        "PeakWorkingSetBytes",
    )
    for token in harness_tokens:
        if token not in harness:
            problems.append(f"harness:token:{token}")
    for forbidden in ("Invoke-WebRequest", "Start-BitsTransfer", "curl.exe", "Start-Sleep", "Remove-Item -Recurse", "latest", "secrets"):
        if forbidden.lower() in harness.lower():
            problems.append(f"harness:forbidden:{forbidden}")
    if harness.count("runtime_claimable") or harness.count("performance_claimable"):
        problems.append("harness:must_not_promote_claims")
    if harness.count("Invoke-Bounded '") != 6 or "$LogRecords.Count + 2 -gt $MaxLogRecords" not in harness:
        problems.append("harness:bounded_log_slots")
    candidate_complete = harness.find("$Candidate.state = 'completed'")
    final_validation = harness.find("Invoke-FinalContractValidation $CandidateReceiptPath")
    atomic_publish = harness.find("[IO.File]::Move($CandidateReceiptPath, $ReceiptPath, $true)")
    if min(candidate_complete, final_validation, atomic_publish) < 0 or not candidate_complete < final_validation < atomic_publish:
        problems.append("harness:completed_publication_order")
    if "$Receipt.state = 'completed'" in harness:
        problems.append("harness:unvalidated_completed_receipt")
    if harness.count("Assert-BenchmarkSourceBindings") < 5:
        problems.append("harness:benchmark_source_recheck")

    benchmark_authority = (root / BENCHMARK_AUTHORITY).read_text(encoding="utf-8")
    for token in ("public static void BuildAndRunNativeBenchmark()", "trace_missing", "--tamandua-player-sha256"):
        if token not in benchmark_authority:
            problems.append(f"benchmark_authority:token:{token}")
    native_adapter = (root / NATIVE_ADAPTER).read_text(encoding="utf-8")
    if 'private const string Library = "tamandua_game_runtime_core";' not in native_adapter:
        problems.append("native_adapter:library")

    problems.extend(receipt_problems(valid_receipt(), schema))
    return sorted(set(problems))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--print-digests", action="store_true")
    parser.add_argument("--receipt", type=pathlib.Path)
    args = parser.parse_args()
    problems = validate(args.root.resolve())
    if args.receipt:
        try:
            schema = strict_json(args.root.resolve() / SCHEMA)
            receipt = strict_json(args.receipt.resolve())
            problems.extend(receipt_problems(receipt, schema))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            problems.append(f"receipt:parse:{type(error).__name__}")
    problems = sorted(set(problems))
    result = {"schema": "tamandua.anti_cheat.unity_native_smoke_source_contract/v1", "valid": not problems, "problems": problems}
    if args.print_digests and not problems:
        result["source_sha256"] = {str(path): sha256(args.root / path) for path in (WORKFLOW, HARNESS, SCHEMA)}
    print(json.dumps(result, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
