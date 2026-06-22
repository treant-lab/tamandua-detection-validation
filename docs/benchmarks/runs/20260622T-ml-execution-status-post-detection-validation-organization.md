# ML Execution Status

Report: `20260622t_ml_execution_status_post_detection_validation_organization`
Generated: `2026-06-22T12:22:25.530777+00:00`

## Claim Boundary

No-execution readiness status only. Does not download malware, train models, run inference, contact live services, or prove production readiness.

## Required Env

- `TAMANDUA_ML_API_KEY`: `missing_or_placeholder`
- `TAMANDUA_ML_DATA_ROOT`: `missing_or_placeholder, outside_repo=False`
- `TAMANDUA_ML_TRAINING_CUTOFF`: `missing_or_placeholder`
- `VIRUSSHARE_API_KEY`: `missing_or_placeholder`

## Next Actions

### 1. set_required_env

- Package: `ml_data_virusshare_fallback`
- Wave: `1`
- Description: Set non-placeholder `TAMANDUA_ML_DATA_ROOT` before launching dependent ML work.
- Env: `TAMANDUA_ML_DATA_ROOT`
- Placeholder: `<external-isolated-malware-lab-data-root>`

### 2. fix_required_env

- Package: `ml_data_virusshare_fallback`
- Wave: `1`
- Description: Point TAMANDUA_ML_DATA_ROOT outside the Git checkout and rerun status.
- Env: `TAMANDUA_ML_DATA_ROOT`

### 3. set_required_env

- Package: `ml_data_virusshare_fallback`
- Wave: `1`
- Description: Set non-placeholder `VIRUSSHARE_API_KEY` before launching dependent ML work.
- Env: `VIRUSSHARE_API_KEY`
- Placeholder: `<virusshare-api-key>`

### 4. wait_for_dependency_evidence

- Package: `ml1_train_candidate_and_model_card`
- Wave: `2`
- Description: Complete `ml_data_governed_acquisition` evidence before launching `ml1_train_candidate_and_model_card` (current evidence_state=`blocked_missing_env`).
- Dependency: `ml_data_governed_acquisition` (`blocked_missing_env`)

### 5. fix_required_env

- Package: `ml1_train_candidate_and_model_card`
- Wave: `2`
- Description: Point TAMANDUA_ML_DATA_ROOT outside the Git checkout and rerun status.
- Env: `TAMANDUA_ML_DATA_ROOT`

### 6. produce_required_artifact

- Package: `ml1_train_candidate_and_model_card`
- Wave: `2`
- Description: Train candidate, run ML-1 with explicit thresholds, then generate the model contract and model card.
- Artifact: `docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json`

### 7. wait_for_dependency_evidence

- Package: `ml2_ml3_onnx_agent_parity`
- Wave: `2`
- Description: Complete `ml1_train_candidate_and_model_card` evidence before launching `ml2_ml3_onnx_agent_parity` (current evidence_state=`blocked_dependency`).
- Dependency: `ml1_train_candidate_and_model_card` (`blocked_dependency`)

### 8. fix_required_env

- Package: `ml2_ml3_onnx_agent_parity`
- Wave: `2`
- Description: Point TAMANDUA_ML_DATA_ROOT outside the Git checkout and rerun status.
- Env: `TAMANDUA_ML_DATA_ROOT`

### 9. produce_required_artifact

- Package: `ml2_ml3_onnx_agent_parity`
- Wave: `2`
- Description: Upgrade Rust toolchain for ONNX parity if `ort` build still requires rustc 1.88 or newer.
- Artifact: `docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json`

### 10. produce_required_artifact

- Package: `ml2_ml3_onnx_agent_parity`
- Wave: `2`
- Description: Upgrade Rust toolchain for ONNX parity if `ort` build still requires rustc 1.88 or newer.
- Artifact: `docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json`

### 11. wait_for_dependency_evidence

- Package: `ml4_live_service_benchmark`
- Wave: `2`
- Description: Complete `ml1_train_candidate_and_model_card` evidence before launching `ml4_live_service_benchmark` (current evidence_state=`blocked_dependency`).
- Dependency: `ml1_train_candidate_and_model_card` (`blocked_dependency`)

### 12. set_required_env

- Package: `ml4_live_service_benchmark`
- Wave: `2`
- Description: Set non-placeholder `TAMANDUA_ML_API_KEY` before launching dependent ML work.
- Env: `TAMANDUA_ML_API_KEY`
- Placeholder: `<ml-service-api-key>`

### 13. wait_for_dependency_evidence

- Package: `ml5_full_pipeline_replay`
- Wave: `3`
- Description: Complete `ml2_ml3_onnx_agent_parity` evidence before launching `ml5_full_pipeline_replay` (current evidence_state=`blocked_dependency`).
- Dependency: `ml2_ml3_onnx_agent_parity` (`blocked_dependency`)

### 14. wait_for_dependency_evidence

- Package: `ml5_full_pipeline_replay`
- Wave: `3`
- Description: Complete `ml4_live_service_benchmark` evidence before launching `ml5_full_pipeline_replay` (current evidence_state=`blocked_dependency`).
- Dependency: `ml4_live_service_benchmark` (`blocked_dependency`)

### 15. produce_required_artifact

- Package: `ml5_full_pipeline_replay`
- Wave: `3`
- Description: Generate replay fixture from agent/server traces after ML-3 and ML-4 are green.
- Artifact: `docs/benchmarks/runs/ml-prod-candidate-v1-ml5-replay-outcomes.json`

### 16. wait_for_dependency_evidence

- Package: `ml6_cross_time_holdout`
- Wave: `3`
- Description: Complete `ml1_train_candidate_and_model_card` evidence before launching `ml6_cross_time_holdout` (current evidence_state=`blocked_dependency`).
- Dependency: `ml1_train_candidate_and_model_card` (`blocked_dependency`)

### 17. set_required_env

- Package: `ml6_cross_time_holdout`
- Wave: `3`
- Description: Set non-placeholder `TAMANDUA_ML_TRAINING_CUTOFF` before launching dependent ML work.
- Env: `TAMANDUA_ML_TRAINING_CUTOFF`
- Placeholder: `<candidate-training-cutoff-iso8601>`

### 18. produce_required_artifact

- Package: `ml6_cross_time_holdout`
- Wave: `3`
- Description: Build prediction fixture from post-cutoff MalwareBazaar/VX/VirusShare/goodware holdouts.
- Artifact: `docs/benchmarks/runs/ml-prod-candidate-v1-ml6-holdout-prediction-outcomes.json`


## Global Launchers

- `ml_readiness_refresh_launcher.ps1`: `exists` - No-execution refresh only. Does not acquire samples, train models, run inference, benchmarks, or live services.
- `ml_benchmark_refresh_launcher.ps1`: `exists` - No-execution benchmark refresh only. Does not acquire samples, publish manifests, train models, run inference, benchmarks, or live services.
- `ml_prelab_validation_launcher.ps1`: `exists` - No-execution pre-lab validation only. Does not acquire samples, publish manifests, train models, run inference, benchmarks, or live services.

## Waves

### Wave 0

- Purpose: Refresh contracts and smoke evidence
- Launch ready: `True`
- Handoff exists: `True`
- Preflight exists: `True`
- Blockers: `none`

### Wave 1

- Purpose: Acquire governed dataset and holdout metadata
- Launch ready: `False`
- Handoff exists: `True`
- Preflight exists: `True`
- Required launchers:
  - `wave_1_real_acquisition_launcher.ps1`: `exists`
  - `wave_1_virusshare_fallback_acquisition_launcher.ps1`: `exists`
  - `wave_1_virusshare_fallback_readiness_launcher.ps1`: `exists`
- Blockers:
  - `package_blocked:ml_data_governed_acquisition:missing_env:TAMANDUA_ML_DATA_ROOT,unsafe_env:TAMANDUA_ML_DATA_ROOT_not_outside_repo,missing_env:VIRUSSHARE_API_KEY`

### Wave 2

- Purpose: Train/evaluate candidate, parity, and service benchmark
- Launch ready: `False`
- Handoff exists: `True`
- Preflight exists: `True`
- Required launchers:
  - `wave_2_ml1_candidate_launcher.ps1`: `exists`
  - `wave_2_ml2_ml3_parity_launcher.ps1`: `exists`
  - `wave_2_ml4_service_launcher.ps1`: `exists`
- Blockers:
  - `package_blocked:ml1_train_candidate_and_model_card:dependency_not_evidence:ml_data_governed_acquisition:blocked_missing_env,missing_env:TAMANDUA_ML_DATA_ROOT,unsafe_env:TAMANDUA_ML_DATA_ROOT_not_outside_repo,missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json`
  - `package_blocked:ml2_ml3_onnx_agent_parity:dependency_not_evidence:ml1_train_candidate_and_model_card:blocked_dependency,missing_env:TAMANDUA_ML_DATA_ROOT,unsafe_env:TAMANDUA_ML_DATA_ROOT_not_outside_repo,missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json,missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json`
  - `package_blocked:ml4_live_service_benchmark:dependency_not_evidence:ml1_train_candidate_and_model_card:blocked_dependency,missing_env:TAMANDUA_ML_API_KEY`

### Wave 3

- Purpose: Full pipeline replay and cross-time holdout
- Launch ready: `False`
- Handoff exists: `True`
- Preflight exists: `True`
- Required launchers:
  - `wave_3_ml5_pipeline_launcher.ps1`: `exists`
  - `wave_3_ml6_holdout_launcher.ps1`: `exists`
- Blockers:
  - `package_blocked:ml5_full_pipeline_replay:dependency_not_evidence:ml2_ml3_onnx_agent_parity:blocked_dependency,dependency_not_evidence:ml4_live_service_benchmark:blocked_dependency,missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-ml5-replay-outcomes.json`
  - `package_blocked:ml6_cross_time_holdout:dependency_not_evidence:ml1_train_candidate_and_model_card:blocked_dependency,missing_env:TAMANDUA_ML_TRAINING_CUTOFF,missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-ml6-holdout-prediction-outcomes.json`

## Packages

### ml0_contracts_and_smoke_refresh

- Wave: `0`
- Status: `evidence_exists`
- Evidence state: `evidence_exists`
- Launch ready: `True`
- Claim boundary: Contract and smoke refresh only; not production model evidence.
- Next action: Regenerate smoke artifacts if contracts drift.
- Blockers: `none`

### ml_data_governed_acquisition

- Wave: `1`
- Status: `blocked_missing_env`
- Evidence state: `blocked_missing_env`
- Launch ready: `False`
- Claim boundary: Governed acquisition only; raw malware must stay outside Git and inside an isolated lab.
- Next action: Run governed MalwareBazaar, vx/InTheWild inventory, and goodware acquisition in the malware lab with an external data root, then publish only manifest/hash evidence.
- Blockers:
  - `missing_env:TAMANDUA_ML_DATA_ROOT`
  - `unsafe_env:TAMANDUA_ML_DATA_ROOT_not_outside_repo`
  - `missing_env:VIRUSSHARE_API_KEY`

### ml_vx_inventory_holdout

- Wave: `1`
- Status: `evidence_exists`
- Evidence state: `evidence_exists`
- Launch ready: `True`
- Claim boundary: Inventory metadata only; does not download, extract, execute, classify, or train on VX samples, and VX samples are not included in train/validation/test splits by default.
- Next action: Create metadata-only inventory and keep selected releases for ML-6 holdout approval.
- Blockers: `none`

### ml1_train_candidate_and_model_card

- Wave: `2`
- Status: `blocked_dependency`
- Evidence state: `blocked_dependency`
- Launch ready: `False`
- Claim boundary: Standalone model quality only; no agent/service/platform impact claim.
- Next action: Train candidate, run ML-1 with explicit thresholds, then generate the model contract and model card.
- Blockers:
  - `dependency_not_evidence:ml_data_governed_acquisition:blocked_missing_env`
  - `missing_env:TAMANDUA_ML_DATA_ROOT`
  - `unsafe_env:TAMANDUA_ML_DATA_ROOT_not_outside_repo`
  - `missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json`

### ml2_ml3_onnx_agent_parity

- Wave: `2`
- Status: `blocked_dependency`
- Evidence state: `blocked_dependency`
- Launch ready: `False`
- Claim boundary: Parity evidence only; blocking rollout waits for signed bundle, runtime provisioning, and canary gates.
- Next action: Upgrade Rust toolchain for ONNX parity if `ort` build still requires rustc 1.88 or newer.
- Blockers:
  - `dependency_not_evidence:ml1_train_candidate_and_model_card:blocked_dependency`
  - `missing_env:TAMANDUA_ML_DATA_ROOT`
  - `unsafe_env:TAMANDUA_ML_DATA_ROOT_not_outside_repo`
  - `missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json`
  - `missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json`

### ml4_live_service_benchmark

- Wave: `2`
- Status: `blocked_dependency`
- Evidence state: `blocked_dependency`
- Launch ready: `False`
- Claim boundary: FastAPI service evidence only; Phoenix proxy comparison remains separate.
- Next action: Start the ML service with the candidate model and run ML-4 with API auth.
- Blockers:
  - `dependency_not_evidence:ml1_train_candidate_and_model_card:blocked_dependency`
  - `missing_env:TAMANDUA_ML_API_KEY`

### ml5_full_pipeline_replay

- Wave: `3`
- Status: `blocked_dependency`
- Evidence state: `blocked_dependency`
- Launch ready: `False`
- Claim boundary: Full pipeline replay evidence only for the controlled fixture corpus and enabled detectors.
- Next action: Generate replay fixture from agent/server traces after ML-3 and ML-4 are green.
- Blockers:
  - `dependency_not_evidence:ml2_ml3_onnx_agent_parity:blocked_dependency`
  - `dependency_not_evidence:ml4_live_service_benchmark:blocked_dependency`
  - `missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-ml5-replay-outcomes.json`

### ml6_cross_time_holdout

- Wave: `3`
- Status: `blocked_dependency`
- Evidence state: `blocked_dependency`
- Launch ready: `False`
- Claim boundary: Robustness evidence only for governed holdout predictions; no zero-day claim by itself.
- Next action: Build prediction fixture from post-cutoff MalwareBazaar/VX/VirusShare/goodware holdouts.
- Blockers:
  - `dependency_not_evidence:ml1_train_candidate_and_model_card:blocked_dependency`
  - `missing_env:TAMANDUA_ML_TRAINING_CUTOFF`
  - `missing_required_artifact:docs/benchmarks/runs/ml-prod-candidate-v1-ml6-holdout-prediction-outcomes.json`
