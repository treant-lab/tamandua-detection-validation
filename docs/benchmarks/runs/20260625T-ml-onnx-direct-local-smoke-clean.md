# ML ONNX Direct Local Smoke Clean - 2026-06-25

Status: completed. This is integration evidence, not a production model-quality
claim.

## Scope

Reran the agent-side ONNX scanner against the local bootstrap KNN export after
the alert relay/socket fixes. The goal was to verify that the agent ONNX binary
still executes and to keep the model-quality boundary explicit.

## Command

```powershell
python .tmp\run_ml_onnx_direct_smoke.py `
  --model apps/tamandua_ml/models/malware_smell_knn.onnx `
  --outdir docs/benchmarks/runs/20260625T-ml-onnx-direct-local-smoke-clean
```

## Result

| Dataset | Samples | Detected malicious | Rate | Avg inference |
| --- | ---: | ---: | ---: | ---: |
| Malware bootstrap | 25 | 25 | 100% | 29.84 ms |
| Goodware bootstrap | 25 | 22 | 88% false positive | 31.32 ms |

Summary artifact:
`docs/benchmarks/runs/20260625T-ml-onnx-direct-local-smoke-clean/summary.json`

## Interpretation

The agent-side ONNX scanner and KNN export are operational, but the current
bootstrap model is not publishable as a production detector because the
goodware false-positive rate remains unacceptable.

Next gate: retrain/calibrate on governed malware/goodware corpora, then rerun
local, Windows, service, and full Tamandua replay benchmarks before publishing
the ML package.
