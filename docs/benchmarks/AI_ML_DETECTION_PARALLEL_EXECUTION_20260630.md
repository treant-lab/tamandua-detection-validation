# AI / ML Detection Parallel Execution Board - 2026-06-30

Status: active execution board.

Claim boundary: this is an engineering execution plan and validation snapshot.
It does not claim production malware-detection quality, acceptable false
positive rate, or release approval for `tamandua-ml`.

## Current Validated State

| Lane | Current proof | Result | Boundary |
| --- | --- | --- | --- |
| Agent AI model scanner | `cargo test --manifest-path apps/tamandua_agent/Cargo.toml --test model_scanner_test -- --nocapture` | 28 passed | Type routing, hashing, cache, and API contract only |
| Agent ML parity fixture bin | `cargo test --manifest-path apps/tamandua_agent/Cargo.toml --bin ml_agent_parity_fixture -- --nocapture` | compiled, 0 tests | Build smoke only |
| ML scanner/unit lane | `python -m pytest apps/tamandua_ml/tests/test_scanner.py apps/tamandua_ml/tests/test_supply_chain_scanner.py apps/tamandua_ml/tests/test_trojai_benchmark.py apps/tamandua_ml/tests/test_model_fingerprinting.py -q --no-cov` | 73 passed | Unit/regression coverage only |
| ML-1 / ONNX contract lane | `python -m pytest apps/tamandua_ml/tests/test_ml1_model_benchmark.py apps/tamandua_ml/tests/test_export_onnx_metadata.py apps/tamandua_ml/tests/test_generate_model_contract.py -q --no-cov` | 17 passed | Contract readiness only |
| AI model scanner harness | `python apps/tamandua_ml/scripts/validate_model_scanners.py` | generated `AI_MODEL_SCANNER_VALIDATION_20260630T134213Z.json` | Small defused corpus only |
| ML mirror gate | `python tools/mirror_deploy/deploy.py verify tamandua-ml` | 13 passed, links OK | Mirror remains HOLD |
| Detection-validation mirror gate | `python tools/mirror_deploy/deploy.py verify tamandua-detection-validation` | links/assets OK | Build deferred by design |
| Public ML claims guard | `python tools/detection_validation/scripts/ml_public_claims_guard.py` | 15 files validated | Claim wording only |

## Parallel Workstreams

| Workstream | Can run in parallel with | Owner lane | Next command or action | Exit gate |
| --- | --- | --- | --- | --- |
| Governed malware/goodware acquisition | AI model scanner corpus expansion, agent socket proof | ML data | Set real `VIRUSSHARE_API_KEY` or restore MalwareBazaar access, then run guarded Wave 1 launcher | Successful external transcript and production manifest |
| Model retraining/calibration | Agent/socket infra proof, AI model scanner expansion | ML training | Run ML-1 only after governed manifest exists | FP budget and model card pass |
| Agent ONNX benchmark | Server socket relay proof, scanner corpus expansion | Agent ML | Re-run `ml_onnx_scan` / telemetry smoke against candidate ONNX after ML-1 export | Agent parity and direct detection pass with acceptable FP |
| Server/API/GUI ML alert proof | ML acquisition/retraining, AI scanner corpus expansion | Platform | Trigger non-deduplicated ML alert through mTLS runtime and capture `alerts:feed` | Fresh alert observed over socket and visible in API/GUI |
| AI model malware scanner expansion | Malware detector retraining, server socket proof | AI security | Add clean/malicious model corpora for GGUF, safetensors, ONNX, pickle, LoRA/config attacks | Repeatable TPR/FPR scorecard with larger corpus |
| Mirror publication | All local validation lanes | Release | Keep `tamandua-ml` held until release gates pass | HOLD removed only after ML-1..ML-6 evidence |

## Known Blocks

- `tamandua-ml` remains on HOLD.
- Current KNN ONNX malware smoke detects malware but has unacceptable goodware
  false positives (`22/25` in the 2026-06-25 smoke).
- Wave 1 governed acquisition is blocked by missing usable malware-source
  secret/access on the current route.
- AI model scanner evidence is limited to `11` malicious and `3` clean defused
  samples.
- Fresh end-to-end proof is still needed where an mTLS agent-created ML alert is
  observed by `alerts:feed` in the same run.
