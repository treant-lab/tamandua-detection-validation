# ML Mirror Publication Audit

Report: `20260622t_ml_mirror_publication_audit_post_detection_validation_organization`
Tamandua ML publication ready: `False`
Tamandua ML decision: `hold_do_not_push`
Recommended next action: `keep_tamandua_ml_mirror_on_hold_until_experimental_release_gate_clears`

## Summary

- Components: `9`
- Push-ready components: `8`
- Held components: `tamandua-ml`
- Dirty components: `none`
- Empty remotes: `tamandua-ml`

## Components

| Component | Hold | Dirty | Remote | Decision |
| --- | ---: | ---: | --- | --- |
| tamandua-agent | `False` | `0` | `has_content` | `ready_to_push` |
| tamandua-core | `False` | `0` | `has_content` | `ready_to_push` |
| tamandua-ctl | `False` | `0` | `has_content` | `ready_to_push` |
| tamandua-gui | `False` | `0` | `has_content` | `ready_to_push` |
| tamandua-browser-extension | `False` | `0` | `has_content` | `ready_to_push` |
| tamandua-server | `False` | `0` | `has_content` | `ready_to_push` |
| tamandua-detection-validation | `False` | `0` | `has_content` | `ready_to_push` |
| tamandua-ml | `True` | `0` | `empty` | `hold_do_not_push` |
| tamandua-community | `False` | `0` | `has_content` | `ready_to_push` |

## Tamandua ML Publication Blockers

- `manifest_hold_active`
- `ml_experimental_release_gate_active`

## Tamandua ML Clearance Criteria

- `ml_manifest_hold_removed`: `False` - Experimental label: sequence heads untrained, external wrappers dormant, and platform readiness audit not complete
- `ml_experimental_release_gate_cleared`: `False` - {"cleared": false, "completion_state": "partial_evidence", "goal_missing_requirements": 9, "latest_platform_readiness_audit": "docs/benchmarks/runs/20260621T-ml-platform-readiness-post-win-template-gate-threading.json", "missing_requirement_ids": ["wave1_governed_acquisition", "wave1_sanitized_manifest", "ml1_model_quality", "ml1_model_contract_and_card", "ml2_pytorch_onnx_parity", "ml3_agent_onnx_parity", "ml4_service_benchmark", "ml5_tamandua_replay", "ml6_cross_time_holdout"], "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION", "next_unproven_requirement_id": "wave1_governed_acquisition", "next_unproven_requirement_phase": "01-wave1-manifest-publication", "production_candidate_ready": false, "proven": 1, "readiness_audit_exists": true, "status": "active", "total_requirements": 10}
- `ml_staging_clean`: `True` - clean
- `ml_artifact_policy_resolved`: `True` - {"current_bootstrap_artifacts": {"encoder.pt": "exclude: 113 MB bootstrap checkpoint, no held-out validation", "markers.pkl": "exclude from source mirror; release artifact only after benchmark gate", "metadata.json": "allowed metadata, must retain bootstrap caveat", "reference_embeddings.npz": "exclude from source mirror; release artifact only after benchmark gate", "static_latent_probe.pkl": "exclude from source mirror; benchmark evidence artifact only"}, "exclude_from_source_mirror": ["*.pt", "*.pth", "models/*.pkl", "models/*.npz", "checkpoints/**", "data/**"], "release_artifact_policy": "Trained weights, markers, and reference embeddings may ship only as signed release artifacts after Wave 1/ML-1 benchmark gates and model-card evidence are green.", "ship_in_source_mirror": ["metadata.json", "sample fixtures", "model contracts", "benchmark reports", "source code"], "source_mirror_policy": "metadata_and_code_only", "status": "resolved"}
- `ml_standalone_validation_defined`: `True` - Standalone validation is metadata/dry-run only: mirror publication audit, benchmark inference dry-run, WIN-TEMPLATE probe, and VX holdout acquisition planner. Experimental sequence heads remain UNTRAINED (501) and external wrappers stay fenced.
- `ml_initial_publication_decision_recorded`: `True` - {"reason": "Do not push the empty tamandua-ml remote until the experimental release gate clears, model-card evidence is current, and the first public source-mirror publish is explicitly approved.", "required_before_approval": ["experimental_hold_removed", "model_card_current", "benchmark_gate_evidence_current", "first_public_source_mirror_publish_approved"], "status": "deferred"}

## Tamandua ML Experimental Gate Evidence

- Readiness audit: `docs/benchmarks/runs/20260621T-ml-platform-readiness-post-win-template-gate-threading.json`
- Production candidate ready: `False`
- Completion state: `partial_evidence`
- Proven requirements: `1/10`
- Missing goal requirements: `9`
- Next unproven requirement: `wave1_governed_acquisition`
- Next phase: `01-wave1-manifest-publication`
- Execute guard env: `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`
- Missing requirement ids: `wave1_governed_acquisition, wave1_sanitized_manifest, ml1_model_quality, ml1_model_contract_and_card, ml2_pytorch_onnx_parity, ml3_agent_onnx_parity, ml4_service_benchmark, ml5_tamandua_replay, ml6_cross_time_holdout`

### Platform Requirements

- `wave1_governed_acquisition` (Wave 1): `incomplete` - Current governed source acquisition completed in isolated lab
- `wave1_sanitized_manifest` (Wave 1): `missing` - Sanitized production candidate dataset manifest published
- `ml1_model_quality` (ML-1): `missing` - Standalone model quality benchmark completed against production candidate dataset
- `ml1_model_contract_and_card` (ML-1): `missing` - Candidate model contract and model card generated from ML-1 evidence
- `ml2_pytorch_onnx_parity` (ML-2): `missing` - PyTorch versus ONNX parity benchmark completed
- `ml3_agent_onnx_parity` (ML-3): `missing` - Agent-side ONNX parity benchmark completed with Rust agent evidence
- `ml4_service_benchmark` (ML-4): `missing` - Live FastAPI ML service benchmark completed
- `ml5_tamandua_replay` (ML-5): `missing` - Full Tamandua replay benchmark completed with ML candidate linked
- `ml6_cross_time_holdout` (ML-6): `missing` - Cross-time holdout benchmark completed against governed holdout
- `public_claim_evidence_boundary` (ML-0): `proven` - Public ML claims remain bounded until all ML-1..ML-6 evidence is proven
