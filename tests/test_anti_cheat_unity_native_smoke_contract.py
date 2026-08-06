import copy
import importlib.util
import json
import pathlib
import shutil

import jsonschema
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "tools/detection_validation/scripts/anti_cheat_unity_native_smoke_contract.py"
FILES = (
    pathlib.Path(".github/workflows/anti-cheat-unity-hosted-smoke.yml"),
    pathlib.Path("sdk/game/unity/scripts/run_unity_native_smoke.ps1"),
    pathlib.Path("schemas/anti_cheat_unity_native_smoke_attempt_v1.schema.json"),
    pathlib.Path("sdk/game/unity/TestProject/Assets/Editor/TamanduaBenchmarkBuild.cs"),
    pathlib.Path("sdk/game/unity/Packages/io.tamandua.game-runtime/Runtime/TamanduaGameNative.cs"),
)


def module():
    spec = importlib.util.spec_from_file_location("anti_cheat_unity_native_smoke_contract", VALIDATOR)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def fixture(tmp_path):
    for relative in FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return tmp_path


def mutate(root, relative, old, new):
    path = root / relative
    source = path.read_text(encoding="utf-8")
    assert old in source
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def test_repository_contract_passes():
    assert module().validate(ROOT) == []


@pytest.mark.parametrize(("old", "new", "problem"), [
    ("workflow_dispatch:", "push:\n    branches: [main]", "workflow:not_dispatch_only"),
    ("ref: ${{ inputs.source_sha }}", "ref: main", "workflow:checkout"),
    ("persist-credentials: false", "persist-credentials: true", "workflow:checkout"),
    ("tamandua-unity-6000-3-16f1", "tamandua-unity", "workflow:runner"),
    ("permissions:\n  contents: read", "permissions: write-all", "workflow:permissions"),
])
def test_workflow_mutations_fail_closed(tmp_path, old, new, problem):
    root = fixture(tmp_path)
    mutate(root, FILES[0], old, new)
    assert problem in module().validate(root)


def test_workflow_preserves_specific_harness_failure_categories():
    source = (ROOT / FILES[0]).read_text(encoding="utf-8")
    assert "if ($receipt.state -eq 'attempt_started')" in source
    assert "elseif ($receipt.state -ne 'completed' -and $receipt.state -ne 'failed')" in source
    assert "benchmark_authority_source_sha256=$null" in source
    assert "trace_writer_source_sha256=$null" in source


@pytest.mark.parametrize(("old", "new"), [
    ("$ExpectedUnityVersion = '6000.3.16f1'", "$ExpectedUnityVersion = 'unknown'"),
    ("$ExpectedTestTotal = 18", "$ExpectedTestTotal = 1"),
    ("$WarmupFrames = 2000", "$WarmupFrames = 10"),
    ("$SampleFrames = 30000", "$SampleFrames = 10"),
    ("$MaxLogBytes = 65536", "$MaxLogBytes = 999999"),
    ("$MaxLogRecords = 12", "$MaxLogRecords = 8"),
    ("'--locked','--offline','--release','--target','x86_64-pc-windows-msvc'", "'--release'"),
])
def test_harness_floor_mutations_fail_closed(tmp_path, old, new):
    root = fixture(tmp_path)
    mutate(root, FILES[1], old, new)
    assert any(problem.startswith("harness:token:") for problem in module().validate(root))


def test_missing_benchmark_is_explicit_fail_closed_category():
    source = (ROOT / FILES[1]).read_text(encoding="utf-8")
    assert "benchmark_receipt_missing" in source
    schema = json.loads((ROOT / FILES[2]).read_text(encoding="utf-8"))
    assert "benchmark_receipt_missing" in schema["properties"]["failure"]["oneOf"][1]["properties"]["category"]["enum"]


def test_source_root_ascent_is_exact_and_source_bound():
    source = (ROOT / FILES[1]).read_text(encoding="utf-8")
    assert "(Join-Path $PSScriptRoot '../../../..')" in source
    assert "(Join-Path $PSScriptRoot '../../..')" not in source
    for token in ("sdk/game/runtime-core/Cargo.toml", "sdk/game/unity/TestProject/ProjectSettings/ProjectVersion.txt", "git -C $Root rev-parse --show-toplevel"):
        assert token in source


def test_log_capacity_covers_every_bounded_phase():
    source = (ROOT / FILES[1]).read_text(encoding="utf-8")
    schema = json.loads((ROOT / FILES[2]).read_text(encoding="utf-8"))
    assert source.count("Invoke-Bounded '") == 6
    assert "$MaxLogRecords = 12" in source
    assert "$LogRecords.Count + 2 -gt $MaxLogRecords" in source
    assert schema["properties"]["logs"]["maxItems"] == 12


def test_plugin_name_architecture_exports_and_embedded_copy_are_bound():
    source = (ROOT / FILES[1]).read_text(encoding="utf-8")
    adapter = (ROOT / FILES[4]).read_text(encoding="utf-8")
    assert 'private const string Library = "tamandua_game_runtime_core";' in adapter
    assert "tamandua_game_runtime_core.dll" in source
    assert "tamandua_game_runtime_v1.dll" not in source
    for token in ("0x8664", "0x20b", "native plugin export set mismatch", "plugin export function/name count mismatch", "plugin export ordinal coverage mismatch", "plugin forwarded export rejected", "Plugins/x86_64/tamandua_game_runtime_core.dll", "embedded native plugin hash mismatch"):
        assert token in source


def test_complete_player_manifest_and_trace_are_required():
    source = (ROOT / FILES[1]).read_text(encoding="utf-8")
    schema = json.loads((ROOT / FILES[2]).read_text(encoding="utf-8"))
    for token in ("Get-PlayerManifestSha256", "$members = @(Get-ChildItem -LiteralPath $root -Recurse -Force)", "GetRelativePath", "player manifest path escaped or duplicated", "player_manifest_sha256", "benchmark_trace_sha256", "trace_missing"):
        assert token in source
    completed_hashes = schema["allOf"][0]["then"]["properties"]["hashes"]["properties"]
    assert set(("player_manifest_sha256", "benchmark_trace_sha256")) <= set(completed_hashes)


def test_exact_benchmark_authority_is_invoked_and_missing_trace_writer_fails_closed():
    source = (ROOT / FILES[1]).read_text(encoding="utf-8")
    for token in ("Tamandua.GameRuntime.Benchmarks.TamanduaBenchmarkBuild.BuildAndRunNativeBenchmark", "'-executeMethod'", "$TraceWriterPath", "$FailureCategory = 'trace_writer_missing'", "benchmark_authority_source_sha256", "trace_writer_source_sha256", "Assert-BenchmarkSourceBindings"):
        assert token in source


def test_final_receipt_is_contract_validated_before_success():
    source = (ROOT / FILES[1]).read_text(encoding="utf-8")
    assert "Invoke-Bounded 'receipt-contract'" in source
    assert "Invoke-FinalContractValidation" in source
    assert "$FailureCategory = 'contract_failed'" in source
    assert "$Receipt.state = 'completed'" not in source
    assert "$CandidateReceiptPath = Join-Path $env:RUNNER_TEMP" in source
    assert source.index("$Candidate.state = 'completed'") < source.index(
        "Invoke-FinalContractValidation $CandidateReceiptPath"
    ) < source.index("[IO.File]::Move($CandidateReceiptPath, $ReceiptPath, $true)")


@pytest.mark.parametrize(("old", "new", "problem"), [
    (
        "$members = @(Get-ChildItem -LiteralPath $root -Recurse -Force)",
        "$members = @(Get-ChildItem -LiteralPath $dataRoot -Recurse -Force)",
        "harness:token:$members = @(Get-ChildItem -LiteralPath $root -Recurse -Force)",
    ),
    (
        "$functionCount = [BitConverter]::ToUInt32($bytes, $exportOffset + 20)",
        "$functionCount = $nameCount",
        "harness:token:$functionCount = [BitConverter]::ToUInt32($bytes, $exportOffset + 20)",
    ),
    (
        "Invoke-FinalContractValidation $CandidateReceiptPath",
        "Invoke-FinalContractValidation $ReceiptPath",
        "harness:completed_publication_order",
    ),
    (
        "Assert-BenchmarkSourceBindings $Candidate.hashes",
        "Write-Output 'skip final source binding'",
        "harness:benchmark_source_recheck",
    ),
])
def test_player_export_completion_and_source_binding_mutations_fail_closed(tmp_path, old, new, problem):
    root = fixture(tmp_path)
    mutate(root, FILES[1], old, new)
    assert problem in module().validate(root)


def test_completed_receipt_requires_18_tests_large_benchmark_and_hashes():
    contract = module()
    schema = json.loads((ROOT / FILES[2]).read_text(encoding="utf-8"))
    receipt = contract.valid_receipt()
    jsonschema.validate(receipt, schema)
    for path, value in (
        (("tests", "total"), 17),
        (("benchmark", "warmup_frames"), 1999),
        (("benchmark", "sample_frames"), 29999),
        (("hashes", "native_plugin_sha256"), None),
        (("hashes", "benchmark_authority_source_sha256"), None),
        (("hashes", "trace_writer_source_sha256"), None),
        (("claims", "performance_claimable"), True),
    ):
        changed = copy.deepcopy(receipt)
        changed[path[0]][path[1]] = value
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(changed, schema)


def test_percentile_order_is_semantically_enforced():
    contract = module()
    schema = json.loads((ROOT / FILES[2]).read_text(encoding="utf-8"))
    receipt = contract.valid_receipt()
    receipt["benchmark"]["frame_delta_ms"] = {"p50": 3, "p95": 2, "p99": 1}
    assert "receipt:percentiles:frame_delta_ms" in contract.receipt_problems(receipt, schema)


def test_completed_test_count_relationship_is_semantically_enforced():
    contract = module()
    schema = json.loads((ROOT / FILES[2]).read_text(encoding="utf-8"))
    receipt = contract.valid_receipt()
    receipt["tests"].update(editmode=17, playmode=0, total=18)
    assert "receipt:tests:relationship" in contract.receipt_problems(receipt, schema)


def test_strict_receipt_parser_rejects_duplicate_and_nonfinite_values(tmp_path):
    contract = module()
    for payload in ('{"state":"completed","state":"failed"}', '{"value":NaN}'):
        path = tmp_path / f"receipt-{abs(hash(payload))}.json"
        path.write_text(payload, encoding="utf-8")
        with pytest.raises(ValueError):
            contract.strict_json(path)


def test_early_failure_receipt_remains_schema_valid_and_nonclaiming():
    contract = module()
    schema = json.loads((ROOT / FILES[2]).read_text(encoding="utf-8"))
    receipt = contract.valid_receipt()
    receipt.update(state="failed", stage="workflow_terminal", benchmark=None,
                   failure={"category": "input", "exit_code": 1})
    receipt["tests"].update(editmode=None, playmode=None, total=None)
    for key in receipt["hashes"]:
        receipt["hashes"][key] = None
    assert contract.receipt_problems(receipt, schema) == []


def test_network_install_secret_and_latest_tokens_are_forbidden(tmp_path):
    for payload in ("\nInvoke-WebRequest https://example.invalid\n", "\ncurl.exe bad\n", "\n$env:secrets_TOKEN\n", "\nlatest\n"):
        root = fixture(tmp_path / str(abs(hash(payload))))
        path = root / FILES[1]
        path.write_text(path.read_text(encoding="utf-8") + payload, encoding="utf-8")
        assert any(problem.startswith("harness:forbidden:") for problem in module().validate(root))
