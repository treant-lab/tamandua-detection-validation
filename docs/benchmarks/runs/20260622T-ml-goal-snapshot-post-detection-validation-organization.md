# ML Goal Snapshot

- `report_id`: `20260622t_ml_goal_snapshot_post_detection_validation_organization`
- `goal_complete`: `False`
- `completion_state`: `partial_evidence`
- `ready_for_completion_claim`: `False`
- `missing_requirements`: `9`
- `usable_required_evidence`: `1/16`
- `next_unproven_requirement`: `wave1_governed_acquisition`
- `next_unproven_execute_guard_env`: `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`
- `wave1_transcript_hashes_match_between_receipts`: `True`
- `goal_snapshot_anchor_check_passed`: `True`

## Missing Requirements
- `wave1_governed_acquisition`
- `wave1_sanitized_manifest`
- `ml1_model_quality`
- `ml1_model_contract_and_card`
- `ml2_pytorch_onnx_parity`
- `ml3_agent_onnx_parity`
- `ml4_service_benchmark`
- `ml5_tamandua_replay`
- `ml6_cross_time_holdout`

## Next Evidence
- `D:\treant\tamandua\docs\benchmarks\runs\20260604T-ml-wave1-real-acquisition-transcript.json`
- `D:\treant\tamandua\docs\benchmarks\runs\20260604T-ml-wave1-acquisition-receipt.json`

## Requirement Evidence Matrix
- `wave1_governed_acquisition` phase=`01-wave1-manifest-publication` status=`missing_evidence` evidence=`2` missing_or_unusable=`2` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_real_acquisition_launcher.ps1`
- `wave1_sanitized_manifest` phase=`01-wave1-manifest-publication` status=`missing_evidence` evidence=`3` missing_or_unusable=`3` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_real_acquisition_launcher.ps1`
- `ml1_model_quality` phase=`02-ml1-candidate-quality` status=`missing_evidence` evidence=`1` missing_or_unusable=`1` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_2_ml1_candidate_launcher.ps1`
- `ml1_model_contract_and_card` phase=`02-ml1-candidate-quality` status=`missing_evidence` evidence=`2` missing_or_unusable=`2` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_2_ml1_candidate_launcher.ps1`
- `ml2_pytorch_onnx_parity` phase=`03-onnx-agent-parity` status=`missing_evidence` evidence=`2` missing_or_unusable=`2` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_2_ml2_ml3_parity_launcher.ps1`
- `ml3_agent_onnx_parity` phase=`03-onnx-agent-parity` status=`missing_evidence` evidence=`2` missing_or_unusable=`2` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_2_ml2_ml3_parity_launcher.ps1`
- `ml4_service_benchmark` phase=`04-service-benchmark` status=`missing_evidence` evidence=`1` missing_or_unusable=`1` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_2_ml4_service_launcher.ps1`
- `ml5_tamandua_replay` phase=`05-platform-replay` status=`missing_evidence` evidence=`1` missing_or_unusable=`1` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_3_ml5_pipeline_launcher.ps1`
- `ml6_cross_time_holdout` phase=`06-cross-time-holdout` status=`missing_evidence` evidence=`1` missing_or_unusable=`1` validation_command=`.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_3_ml6_holdout_launcher.ps1`
- `public_claim_evidence_boundary` phase=`00-public-claim-boundary` status=`proven` evidence=`1` missing_or_unusable=`0` validation_command=``

## Checks
- `pass` `master_handoff_valid`: docs\benchmarks\runs\20260621T-ml-execution-master-handoff-post-win-template-gate-threading.json (jsonschema+built-in)
- `pass` `goal_not_complete`: {"completion_state": "partial_evidence", "goal_complete": false}
- `pass` `next_unproven_requirement_is_wave1`: wave1_governed_acquisition
- `pass` `shared_snapshot_matches_master`: {"mismatched_fields": []}
- `pass` `goal_snapshot_anchor_check_passed`: {"master_summary_wave1_goal_snapshot_anchor_check_passed": true}
