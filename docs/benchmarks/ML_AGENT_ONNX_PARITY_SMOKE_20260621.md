# ML Agent ONNX Parity Smoke - 2026-06-21

## Scope

This note records a safe rerun of the Rust agent-side ONNX parity smoke path.
It does not use raw malware, does not contact WIN-TEMPLATE, and does not satisfy
the canonical `ml-prod-candidate-v1` ML-3 gate.

The run proves that the agent can load the frozen smoke ONNX fixture and produce
the same practical outputs recorded in the fixture within tolerance.

## Commands

```powershell
cargo test --manifest-path apps\tamandua_agent\Cargo.toml --test ml_agent_parity_fixture_contract --no-default-features
cargo run --manifest-path apps\tamandua_agent\Cargo.toml --bin ml_agent_parity_fixture --no-default-features -- --fixture docs\benchmarks\runs\20260604T174850Z-ml-agent-parity-fixture.json
$env:ORT_DYLIB_PATH = 'C:\Python310\lib\site-packages\onnxruntime\capi\onnxruntime.dll'
cargo run --manifest-path apps\tamandua_agent\Cargo.toml --bin ml_agent_onnx_parity --no-default-features --features onnx -- --fixture docs\benchmarks\runs\20260604T174850Z-ml-agent-parity-fixture.json --output docs\benchmarks\runs\20260621T-agent-onnx-parity-smoke-rerun.json
python apps\tamandua_ml\scripts\ml3_agent_parity_report.py --fixture docs\benchmarks\runs\20260604T174850Z-ml-agent-parity-fixture.json --cargo-output docs\benchmarks\runs\20260621T-agent-parity-fixture-rerun.log --agent-results docs\benchmarks\runs\20260621T-agent-onnx-parity-smoke-rerun.json --win-template-probe docs\benchmarks\runs\20260620T-win-template-ml-probe-local-inference.json --output docs\benchmarks\runs\20260621T-ml3-agent-onnx-parity-smoke-rerun.json --markdown-output docs\benchmarks\runs\20260621T-ml3-agent-onnx-parity-smoke-rerun.md --report-id 20260621t_ml3_agent_onnx_parity_smoke_rerun --model-version ml-smoke-fixture-v1 --git-commit 7f191885 --require-cargo-fixture-validation
python tools\detection_validation\validate_ml_contracts.py --benchmark-report docs\benchmarks\runs\20260621T-ml3-agent-onnx-parity-smoke-rerun.json --agent-parity-fixture docs\benchmarks\runs\20260604T174850Z-ml-agent-parity-fixture.json
```

## Result

| Check | Result |
| --- | --- |
| Rust fixture contract test | pass, 1 test |
| Rust fixture CLI | pass, 6 samples |
| Rust ONNX parity CLI | pass |
| ML-3 report quality gate | pass |
| Contract validation | pass |

Agent ONNX parity metrics:

| Metric | Value |
| --- | --- |
| Fixture id | `20260604t174850z_ml_agent_parity_fixture` |
| Sample count | 6 |
| Verdict matches | 6 |
| Verdict agreement | 1.0 |
| Max absolute probability delta | 0.000027954578 |
| Allowed max absolute probability delta | 0.0001 |

The regenerated ML-3 report also attached the latest safe WIN-TEMPLATE local
fixture probe, whose local checkpoint inference result was 3 benign fixtures and
1 high-entropy control predicted malicious.

## Post Staging-Clean Rerun

After the `tamandua-ml` mirror staging was cleaned locally, the agent-side smoke
was rerun with ONNX Runtime `1.23.2` from
`C:\Python310\Lib\site-packages\onnxruntime\capi\onnxruntime.dll`.
The report keeps the fixture's original `onnxruntime_version` separately as
fixture metadata (`1.21.0`) and records the local runner package/DLL under
`runner_onnxruntime_python_version` and `runner_ort_dylib_path`.

Artifacts:

- ONNX parity results: `docs/benchmarks/runs/20260621T-agent-onnx-parity-smoke-post-staging-clean.json`
- Fixture CLI log: `docs/benchmarks/runs/20260621T-agent-parity-fixture-post-staging-clean.log`
- ML-3 smoke report: `docs/benchmarks/runs/20260621T-ml3-agent-onnx-parity-smoke-post-staging-clean.json`
- ML-3 smoke markdown: `docs/benchmarks/runs/20260621T-ml3-agent-onnx-parity-smoke-post-staging-clean.md`

Validation:

```powershell
python tools\detection_validation\validate_ml_contracts.py --benchmark-report docs\benchmarks\runs\20260621T-ml3-agent-onnx-parity-smoke-post-staging-clean.json --agent-parity-fixture docs\benchmarks\runs\20260604T174850Z-ml-agent-parity-fixture.json
```

Result: `pass`.

## WIN-TEMPLATE Local Inference Rerun

The WIN-TEMPLATE probe was rerun with local checkpoint inference against four
declared non-malware fixtures. The model completed inference and produced three
benign predictions plus one malicious prediction on the seeded high-entropy
control fixture.

Artifacts:

- WIN-TEMPLATE probe: `docs/benchmarks/runs/20260621T-win-template-ml-probe-local-inference-rerun.json`
- Inference benchmark contract: `docs/benchmarks/runs/20260621T-ml-inference-benchmark-contract-post-win-template-rerun.json`
- ML-3 smoke report with WIN-TEMPLATE rerun: `docs/benchmarks/runs/20260621T-ml3-agent-onnx-parity-smoke-with-win-template-rerun.json`
- ML-3 smoke markdown: `docs/benchmarks/runs/20260621T-ml3-agent-onnx-parity-smoke-with-win-template-rerun.md`

Validation:

```powershell
python tools\detection_validation\validate_ml_contracts.py --benchmark-report docs\benchmarks\runs\20260621T-ml3-agent-onnx-parity-smoke-with-win-template-rerun.json --agent-parity-fixture docs\benchmarks\runs\20260604T174850Z-ml-agent-parity-fixture.json --ml-win-template-probe docs\benchmarks\runs\20260621T-win-template-ml-probe-local-inference-rerun.json
```

Result: `pass`.

This is not a detection proof. Because all WIN-TEMPLATE fixtures are declared
non-malware, the malicious prediction is tracked as a false-positive candidate
and the production gate impact remains `no_go_for_detection_claims`.

## Claim Boundary

This is agent-side smoke parity for `ml-smoke-fixture-v1`. It proves that the
current Rust ONNX path can consume the frozen ML-3 fixture and stay within the
declared probability tolerance.

It does not prove production detection quality, does not prove telemetry from a
live Windows endpoint, and does not unblock ML-5 platform replay. The production
ML-3 gate still needs `ml-prod-candidate-v1` artifacts generated after Wave 1
governed acquisition and ML-1 model-quality evidence.
