# ML Benchmark Actionability Audit

Report: `20260621t_ml_benchmark_actionability_audit_agent_rush`
Generated: `2026-06-22T02:14:58.322206+00:00`
Actionable: `True`

## Claim Boundary

No-execution actionability audit only. It verifies validation-only command exposure and does not run launchers, set env vars, execute guards, acquire data, train, infer, benchmark, or contact services.

## Summary

- `queue_items`: `43`
- `queue_items_with_resolution_command`: `43`
- `queue_items_without_resolution_command`: `0`
- `critical_path_steps`: `23`
- `critical_path_steps_with_resolution_command`: `23`
- `critical_path_steps_without_resolution_command`: `0`
- `handoff_files`: `23`
- `handoff_files_with_resolution_command`: `23`
- `validation_command_count`: `23`
- `validation_commands_are_validation_only`: `True`
- `guarded_execute_commands_exposed`: `17`
- `non_guarded_resolution_commands`: `6`
- `env_validation_commands`: `2`
- `env_validation_commands_redacted`: `True`
- `env_validation_commands_parse_cutoff`: `True`
- `evidence_usable_for_goal`: `0`
- `standalone_detection_surface_covered`: `True`
- `agent_onnx_detection_surface_covered`: `True`
- `tamandua_detection_surface_covered`: `True`
- `benchmark_detection_surface_contract_ready`: `True`
- `actionability_gap_count`: `0`
- `check_count`: `10`
- `passed_checks`: `10`
- `failed_checks`: `0`
- `goal_complete`: `False`
- `completion_state`: `partial_evidence`
- `goal_usable_required_evidence`: `1`
- `goal_required_evidence_total`: `16`
- `next_unproven_requirement_id`: `wave1_governed_acquisition`
- `next_unproven_execute_guard_env`: `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`

## Checks

- `queue_all_items_have_resolution_command` passed=`True`: 43/43 queue items expose commands
- `critical_path_all_steps_have_resolution_command` passed=`True`: 23/23 critical steps expose commands
- `handoff_all_files_have_resolution_command` passed=`True`: 23/23 handoff files expose commands
- `handoff_validation_commands_are_validation_only` passed=`True`: 23 validation commands inspected
- `critical_handoff_consistency_passed` passed=`True`: critical path handoff consistency artifact is pass
- `env_validation_commands_present` passed=`True`: 2/2 env validation commands present
- `api_key_validation_redacts_secret` passed=`True`: TAMANDUA_ML_API_KEY command redacts value
- `training_cutoff_validation_parses_iso8601` passed=`True`: TAMANDUA_ML_TRAINING_CUTOFF command parses timestamp
- `no_goal_evidence_claimed` passed=`True`: usable evidence across critical path and handoffs=0
- `benchmark_detection_surface_contract_ready` passed=`True`: critical path covers standalone, agent ONNX, and Tamandua benchmark surfaces
