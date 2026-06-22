# ML Benchmark Lane Rollup

Report: `20260621t_ml_benchmark_lane_rollup_agent_rush`
Generated: `2026-06-22T02:14:58.285888+00:00`

## Claim Boundary

No-execution ML benchmark lane rollup only. It summarizes existing matrix and unblock status artifacts without running launchers, acquisition, publication, training, inference, benchmarks, or live services.

## Summary

- `total_lanes`: `7`
- `evidence_exists_lanes`: `1`
- `blocked_lanes`: `6`
- `ready_lanes`: `1`
- `standalone_detection_lanes`: `1`
- `agent_onnx_detection_lanes`: `2`
- `tamandua_detection_lanes`: `3`
- `standalone_detection_surface_covered`: `True`
- `agent_onnx_detection_surface_covered`: `True`
- `tamandua_detection_surface_covered`: `True`
- `benchmark_detection_surface_contract_ready`: `True`
- `total_pending_items`: `43`
- `upstream_ready_validation_only`: `1`
- `upstream_blocked`: `5`
- `contract_packets_all_validated`: `True`
- `contract_packets_validated`: `3`
- `next_operator_publication_decision`: `hold_do_not_push`
- `ml2_ml3_agent_smoke_unblocks_production`: `False`
- `pending_by_category`: `{'dependency': 10, 'artifact': 22, 'env': 2, 'other': 9}`
- `resolved_by_category`: `{'dependency': 0, 'artifact': 0, 'env': 0, 'other': 0}`
- `dependency_pending`: `10`
- `artifact_pending`: `22`
- `env_pending`: `2`
- `goal_complete`: `False`
- `completion_state`: `partial_evidence`
- `goal_usable_required_evidence`: `1`
- `goal_required_evidence_total`: `16`
- `next_unproven_requirement_id`: `wave1_governed_acquisition`
- `next_unproven_execute_guard_env`: `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`

## Source Status Summary

- `benchmark_execution_matrix_validation`: `jsonschema+built-in`
- `benchmark_unblock_validation_status_validation`: `jsonschema+built-in`
- `benchmark_unblock_validation_status_consistency_validation`: `jsonschema+built-in`
- `matrix_validated`: `True`
- `status_validated`: `True`
- `status_consistency_validated`: `True`
- `source_alignment_verified`: `True`
- `source_status_pending_items`: `43`
- `rollup_pending_items`: `43`
- `pending_item_ids`: `['ml-benchmark-unblock-001', 'ml-benchmark-unblock-011', 'ml-benchmark-unblock-035', 'ml-benchmark-unblock-036', 'ml-benchmark-unblock-037', 'ml-benchmark-unblock-002', 'ml-benchmark-unblock-003', 'ml-benchmark-unblock-012', 'ml-benchmark-unblock-013', 'ml-benchmark-unblock-014', 'ml-benchmark-unblock-015', 'ml-benchmark-unblock-038', 'ml-benchmark-unblock-004', 'ml-benchmark-unblock-005', 'ml-benchmark-unblock-016', 'ml-benchmark-unblock-017', 'ml-benchmark-unblock-018', 'ml-benchmark-unblock-019', 'ml-benchmark-unblock-039', 'ml-benchmark-unblock-006', 'ml-benchmark-unblock-007', 'ml-benchmark-unblock-020', 'ml-benchmark-unblock-021', 'ml-benchmark-unblock-022', 'ml-benchmark-unblock-033', 'ml-benchmark-unblock-040', 'ml-benchmark-unblock-008', 'ml-benchmark-unblock-009', 'ml-benchmark-unblock-023', 'ml-benchmark-unblock-024', 'ml-benchmark-unblock-025', 'ml-benchmark-unblock-026', 'ml-benchmark-unblock-027', 'ml-benchmark-unblock-028', 'ml-benchmark-unblock-041', 'ml-benchmark-unblock-042', 'ml-benchmark-unblock-010', 'ml-benchmark-unblock-029', 'ml-benchmark-unblock-030', 'ml-benchmark-unblock-031', 'ml-benchmark-unblock-032', 'ml-benchmark-unblock-034', 'ml-benchmark-unblock-043']`
- `matrix_lanes`: `7`
- `rollup_lanes`: `7`
- `ready_lane_ids`: `['ML-0']`
- `blocked_lane_ids`: `['ML-1', 'ML-2', 'ML-3', 'ML-4', 'ML-5', 'ML-6']`
- `standalone_detection_lane_ids`: `['ML-1']`
- `agent_onnx_detection_lane_ids`: `['ML-3', 'ML-5']`
- `tamandua_detection_lane_ids`: `['ML-3', 'ML-4', 'ML-5']`
- `ready_lanes`: `1`
- `blocked_lanes`: `6`
- `standalone_detection_lanes`: `1`
- `agent_onnx_detection_lanes`: `2`
- `tamandua_detection_lanes`: `3`
- `standalone_detection_surface_covered`: `True`
- `agent_onnx_detection_surface_covered`: `True`
- `tamandua_detection_surface_covered`: `True`
- `benchmark_detection_surface_contract_ready`: `True`
- `upstream_ready_validation_only`: `1`
- `upstream_blocked`: `5`
- `contract_packets_all_validated`: `True`
- `contract_packets_validated`: `3`
- `next_operator_publication_decision`: `hold_do_not_push`
- `ml2_ml3_agent_smoke_unblocks_production`: `False`
- `pending_by_category`: `{'dependency': 10, 'artifact': 22, 'env': 2, 'other': 9}`
- `resolved_by_category`: `{'dependency': 0, 'artifact': 0, 'env': 0, 'other': 0}`
- `dependency_pending`: `10`
- `artifact_pending`: `22`
- `env_pending`: `2`
- `goal_complete`: `False`
- `completion_state`: `partial_evidence`
- `goal_missing_requirements`: `9`
- `goal_required_evidence_total`: `16`
- `goal_present_required_evidence`: `5`
- `goal_usable_required_evidence`: `1`
- `goal_missing_required_evidence`: `11`
- `goal_unusable_present_required_evidence`: `4`
- `next_unproven_requirement_id`: `wave1_governed_acquisition`
- `next_unproven_requirement_phase`: `01-wave1-manifest-publication`
- `next_unproven_execute_guard_env`: `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`
- `missing_requirement_ids`: `['wave1_governed_acquisition', 'wave1_sanitized_manifest', 'ml1_model_quality', 'ml1_model_contract_and_card', 'ml2_pytorch_onnx_parity', 'ml3_agent_onnx_parity', 'ml4_service_benchmark', 'ml5_tamandua_replay', 'ml6_cross_time_holdout']`
- `evidence_status_summary`: `{'total_required_evidence': 16, 'present_required_evidence': 5, 'usable_required_evidence': 1, 'missing_required_evidence': 11, 'unusable_present_required_evidence': 4, 'by_status': {'blocked_artifact': 4, 'missing': 11, 'usable': 1}}`
- `next_unproven_requirement`: `{'id': 'wave1_governed_acquisition', 'phase': '01-wave1-manifest-publication', 'phase_state': 'ready_validation_only', 'execute_guard_env': 'TAMANDUA_ALLOW_ML_REAL_ACQUISITION', 'pending_targets': ['manifest_publish_receipt_incomplete', 'missing_canonical_dataset_manifest'], 'required_evidence': ['D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-real-acquisition-transcript.json', 'D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-acquisition-receipt.json'], 'missing_or_unusable_evidence': ['D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-real-acquisition-transcript.json', 'D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-acquisition-receipt.json']}`

## Lanes

- `ML-0` `pipeline_smoke` status=`evidence_exists` mode=`pipeline_smoke` ready=`True` pending=`0` dependency=`0` artifact=`0` env=`0`
- `ML-1` `isolated_model` status=`blocked_artifact` mode=`standalone_model_detection` ready=`False` pending=`5` dependency=`1` artifact=`1` env=`0`
  - next: `ml-benchmark-unblock-001`, `ml-benchmark-unblock-011`, `ml-benchmark-unblock-035`
- `ML-2` `onnx_parity` status=`blocked_artifact` mode=`pytorch_onnx_parity` ready=`False` pending=`7` dependency=`2` artifact=`4` env=`0`
  - next: `ml-benchmark-unblock-002`, `ml-benchmark-unblock-003`, `ml-benchmark-unblock-012`
- `ML-3` `agent_local` status=`blocked_artifact` mode=`agent_onnx_local_detection` ready=`False` pending=`7` dependency=`2` artifact=`4` env=`0`
  - next: `ml-benchmark-unblock-004`, `ml-benchmark-unblock-005`, `ml-benchmark-unblock-016`
- `ML-4` `service_api` status=`blocked_env` mode=`tamandua_service_detection` ready=`False` pending=`7` dependency=`2` artifact=`3` env=`1`
  - next: `ml-benchmark-unblock-006`, `ml-benchmark-unblock-007`, `ml-benchmark-unblock-020`
- `ML-5` `platform_replay` status=`blocked_artifact` mode=`tamandua_end_to_end_replay` ready=`False` pending=`10` dependency=`2` artifact=`6` env=`0`
  - next: `ml-benchmark-unblock-008`, `ml-benchmark-unblock-009`, `ml-benchmark-unblock-023`
- `ML-6` `cross_time_holdout` status=`blocked_env` mode=`cross_time_holdout_detection` ready=`False` pending=`7` dependency=`1` artifact=`4` env=`1`
  - next: `ml-benchmark-unblock-010`, `ml-benchmark-unblock-029`, `ml-benchmark-unblock-030`
