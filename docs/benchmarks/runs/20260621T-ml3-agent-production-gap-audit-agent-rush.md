# ML-3 Agent Production Gap Audit

Report: `20260621t_ml3_agent_production_gap_audit_agent_rush`
Status: `blocked`
Quality gate: `pass`
Unblocks ML-5: `False`

No-execution ML-3 production gap audit. It records existing smoke parity and missing production-candidate artifacts; it does not run inference, contact WIN-TEMPLATE, train, publish ML artifacts, or unblock ML-5.

## Checks
- `pass` smoke_agent_onnx_parity_present: {"model_version": "ml-smoke-fixture-v1", "smoke_quality_gate": "pass"}
- `pass` win_template_false_positive_context_attached: {"artifact_names": ["agent_onnx_parity_results", "agent_parity_fixture", "agent_parity_fixture_cli_log", "win_template_ml_probe"]}
- `pass` smoke_report_does_not_unblock_production: ML-3 smoke agent-side evidence with WIN-TEMPLATE local fixture inference rerun. This proves Rust ONNX parity only against the frozen synthetic fixture and records local checkpoint behavior on non-malware WIN-TEMPLATE fixtures. It does not satisfy the canonical ml-prod-candidate-v1 ML-3 gate or prove production detection.
- `pass` canonical_ml3_agent_parity_report_missing: docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json
- `pass` candidate_model_contract_missing: docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json
- `pass` candidate_onnx_metadata_missing: docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json

## Blockers
- `missing_canonical_ml3_agent_parity_report`
- `missing_candidate_model_contract`
- `missing_candidate_onnx_metadata`
- `upstream_ml1_candidate_not_available`
