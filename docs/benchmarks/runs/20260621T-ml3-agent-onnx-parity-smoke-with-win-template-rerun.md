# ML-3 Agent Parity Report

Report: `20260621t_ml3_agent_onnx_parity_smoke_with_win_template_rerun`
Lane: `ML-3`
Quality gate: `pass`
Fixture: `docs/benchmarks/runs/20260604T174850Z-ml-agent-parity-fixture.json`
Samples: `6`

ML-3 smoke agent-side evidence with WIN-TEMPLATE local fixture inference rerun. This proves Rust ONNX parity only against the frozen synthetic fixture and records local checkpoint behavior on non-malware WIN-TEMPLATE fixtures. It does not satisfy the canonical ml-prod-candidate-v1 ML-3 gate or prove production detection.

## Checks
- `pass` production_candidate_fixture_identity: {"fixture_id": "20260604t174850z_ml_agent_parity_fixture", "fixture_path": "docs/benchmarks/runs/20260604T174850Z-ml-agent-parity-fixture.json", "identity_matches_model_version": false, "model_contract_ref": "docs/apps/tamandua_ml/examples/ml_model_contract_malware_smell_onnx_v1.json", "model_version": "ml-smoke-fixture-v1", "onnx_model_path": "docs\\benchmarks\\runs\\20260604T173304Z-ml-pipeline-smoke-artifacts\\malware_smell.onnx", "requirement": "Production candidate ML-3 reports must consume a fixture, model, metadata, or contract whose identity includes ml-prod-candidate-v1. Smoke fixture parity cannot unblock ML-5.", "requires_candidate_identity": false}
- `pass` fixture_schema_contract: Fixture loaded from docs/benchmarks/runs/20260604T174850Z-ml-agent-parity-fixture.json with 6 samples.
- `pass` rust_fixture_cli: {"expected_sample_count": 6, "fixture_validated": true, "present": true, "sample_count": 6, "sample_count_matches_fixture": true}
- `pass` rust_agent_onnx_parity: {"allowed_max_abs_probability_delta": 0.0001, "expected_sample_count": 6, "fixture_max_abs_probability_delta": 0.0001, "fixture_verdict_agreement_required": 1.0, "max_abs_probability_delta": 2.7954578e-05, "max_abs_probability_delta_within_tolerance": true, "passed": true, "path": "docs/benchmarks/runs/20260621T-agent-onnx-parity-smoke-post-staging-clean.json", "present": true, "sample_count": 6, "sample_count_matches_fixture": true, "verdict_agreement": 1.0, "verdict_agreement_within_tolerance": true}
- `pass` win_template_ml_probe: {"agent_id": "5a2c7e97-cd1c-449f-b85b-8fb1711798b9", "all_fixtures_declared_non_malware": true, "endpoint_contacted": false, "false_positive_candidate_sample_ids": ["win_template_seeded_high_entropy_control"], "fixture_count": 4, "hostname": "WIN-TEMPLATE", "inference_status": "completed", "malicious_prediction_count_on_safe_fixtures": 1, "path": "docs/benchmarks/runs/20260621T-win-template-ml-probe-local-inference-rerun.json", "prediction_count": 4, "present": true, "production_gate_impact": "no_go_for_detection_claims", "safe_fixture_behavior_summary_present": true, "status": "pass"}
- `pass` production_claim_boundary: ML-3 smoke agent-side evidence with WIN-TEMPLATE local fixture inference rerun. This proves Rust ONNX parity only against the frozen synthetic fixture and records local checkpoint behavior on non-malware WIN-TEMPLATE fixtures. It does not satisfy the canonical ml-prod-candidate-v1 ML-3 gate or prove production detection.
