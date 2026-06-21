# ML Agent Rush Benchmark Execution Packet

Status: coordination packet only.

Claim boundary: this packet does not acquire samples, train, export ONNX,
contact services, replay telemetry, or prove detection.

## Current Evidence

WIN-TEMPLATE local inference completed against four fixtures declared
non-malware. The current result is three benign predictions and one malicious
prediction on `win_template_seeded_high_entropy_control`.

That malicious prediction is a false-positive candidate, not detection proof.
Production detection claims remain blocked.

## Contracts Created

| Lane | Artifact | Status |
| --- | --- | --- |
| ML-1 | `docs/benchmarks/runs/20260621T-ml1-model-benchmark-contract-agent-rush.json` | `not_run` |
| ML-2 | `docs/benchmarks/runs/20260621T-ml-inference-benchmark-contract-post-win-template-rerun.json` | `not_run` |
| ML-3 | `docs/benchmarks/runs/20260621T-ml3-agent-onnx-parity-smoke-with-win-template-rerun.json` | smoke pass, production blocked |
| ML-4 | `docs/benchmarks/runs/20260621T-ml4-api-benchmark-contract-agent-rush.json` | `not_run` |
| ML-5 | `docs/benchmarks/runs/20260621T-ml5-pipeline-benchmark-contract-agent-rush.json` | `not_run` |
| ML-6 | `docs/benchmarks/runs/20260621T-ml6-holdout-benchmark-contract-agent-rush.json` | `not_run` |

## Blockers

- Missing canonical dataset manifest:
  `docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json`
- Missing production candidate ONNX artifact and metadata.
- Missing ML-1 production report, model contract, and model card.
- Missing ML-3 production agent parity report.
- Missing ML-4 service benchmark report.
- Missing ML-5 replay outcomes and ML-6 holdout outcomes.
- WIN-TEMPLATE local fixture result currently includes a false-positive
  candidate on non-malware input.

## Go/No-Go

| Surface | Decision |
| --- | --- |
| Agent smoke parity | go |
| Production detection claim | no-go |
| `tamandua-ml` public mirror push | no-go |
| Detection-validation evidence publish | go |
| Next unblock | Wave 1 governed acquisition |

## Next Execution

After Wave 1 publishes the canonical sanitized manifest, run the canonical
ML-1 report first. Do not run ML-2 through ML-6 as production gates until ML-1,
model contract, model card, and ONNX export evidence are present.
