# Detection Validation Probe Catalog

The standalone mirror keeps executable probes, validators, generators, and
shared helpers under `scripts/`. Pytest coverage lives under `tests/`. This
catalog should be updated whenever a new probe, validator, generated-contract
helper, or test family is added.

## Root Groups

| Group | Files | Purpose |
| --- | ---: | --- |
| Tests | 86 | `tests/test_*.py` coverage for standalone contracts, schemas, probes, publication audits, and ML gates. |
| Generators and probes | 51 | `scripts/*.py` executable validation probes, roadmap generators, benchmark scorecards, and readiness summaries. |
| Support | 23 | `scripts/*.py` shared runners, adapters, root resolution, migration helpers, and operational utilities. |
| Validators | 8 | `scripts/*.py` contract and metadata validators intended for CI or mirror publication gates. |
| Docs | 5 | Mirror usage, repository structure, contribution, external-rule, and probe catalog documentation. |
| Configs | 1 | Top-level integration metadata. |

## Operational Entry Points

| File | Role |
| --- | --- |
| `scripts/tamandua_detection_validation.py` | Main validation runner for profile-driven execution and evidence generation. |
| `scripts/run_preflight_work_package.py` | Large preflight orchestrator for readiness work packages. |
| `scripts/validate_ml_contracts.py` | ML evidence contract validator used by ML and detection-validation mirrors. |
| `scripts/validation_status_consistency.py` | Cross-artifact consistency checks for generated validation status. |
| `scripts/root_resolver.py` | Standalone/monorepo path resolver used by validators and tests. |
| `scripts/mobile_app_guard_benchmark_gate.py` | Aggressive Mobile App Guard synthetic replay benchmark gate for category coverage, claim labels, privacy constraints, and goodware FP guardrails. |
| `scripts/driver_kernel_containment_claim_guard.py` | Document-level guard that keeps driver/kernel containment roadmap language bounded to defensive, lab-validated, rollback-aware claims. |
| `scripts/plugins_bof_static_readiness_probe.py` | Static Plugins/BOF/dynamic module boundary gate; verifies the lane remains design-dormant/lab and does not claim runtime execution readiness. |
| `scripts/posture_inventory_compliance_readiness_gate.py` | Synthetic Wazuh-style posture/inventory/compliance contract gate for software, license, CVE, compliance, config, FIM, and fleet freshness evidence boundaries. |

## Platform Probes

| Domain | Representative files |
| --- | --- |
| Windows lab and QGA | `windows_lab_execution_readiness_probe.py`, `windows_proxmox_qga_readiness_probe.py`, `windows_qga_agent_service_probe.py`, `windows_qga_start_foreground_agent.py`, `windows_agent_connection_stability_probe.py` |
| Linux/eBPF | `linux_ebpf_readiness_probe.py` |
| macOS | `macos_backend_readiness_probe.py`, `macos_release_artifact_preflight.py`, `generate_macos_local_contract_benchmark.py`, `generate_macos_parity_profiles.py` |
| Agent/runtime capability | `agent_platform_capabilities_live_api_probe.py`, `agent_platform_capabilities_runtime_probe.py`, `agent_driver_reliability_fixture_probe.py`, `platform_capabilities_probe.py` |
| Driver/kernel containment | `driver_kernel_containment_claim_guard.py` for roadmap claim boundaries around driver/module inventory, kernel posture, OS-supported containment, rollback, and rebuild guidance |
| Plugins/BOF/dynamic modules | `plugins_bof_static_readiness_probe.py` |
| Control plane and tenancy | `control_plane_tenant_safety_probe.py`, `control_plane_two_tenant_fixture_probe.py`, `platform_capability_evidence_fixture_probe.py` |
| Resilience/release | `crash_resilience_fixture_probe.py`, `fresh_restore_provenance_probe.py`, `release_resilience_static_probe.py`, `release_operations_fixture_probe.py`, `generate_release_reliability_gate.py` |

## Detection Content And Replay

| Domain | Representative files |
| --- | --- |
| ATT&CK and rule coverage | `attack_coverage_matrix.py`, `generate_external_rule_coverage_map.py`, `external_rule_event_contracts.py`, `validate_external_rule_readiness.py` |
| Detection governance | `detection_content_governance_probe.py`, `detection_rule_evidence_backlog.py`, `detection_rule_evidence_matrix.py`, `detection_rule_wave_fixture_plan.py` |
| Replay and telemetry | `event_envelope_replay_probe.py`, `historical_replay_adapter_probe.py`, `telemetry_replay_executor.py`, `telemetry_replay_readiness_probe.py`, `validate_replay_fixtures.py` including App Guard/RASP protected WebView replay fixtures, `mobile_app_guard_benchmark_gate.py` for aggressive mobile shielding benchmark coverage |
| DFIR | `dfir_collection_fixture_probe.py`, `dfir_readiness_probe.py` |
| Fleet and scale | `fleet_inventory_probe.py`, `fleet_scale_isolation_fixture_probe.py` |
| Posture/inventory/compliance | `posture_inventory_compliance_readiness_gate.py` |

## ML Validation

| Domain | Representative files |
| --- | --- |
| Public claim guard | `scripts/ml_public_claims_guard.py`, `tests/test_ml_public_claims_guard.py` |
| Training roadmap | `tests/test_ml_training_pipeline_roadmap.py` |
| Dataset/acquisition contracts | `tests/test_validate_ml_acquisition_dry_run.py`, `tests/test_validate_ml_dataset_manifest.py`, `tests/test_validate_ml_vx_underground_inventory.py`, `tests/test_validate_ml_virusshare_fallback_contracts.py` |
| Model and benchmark contracts | `tests/test_validate_ml_model_contract.py`, `tests/test_validate_ml_benchmark_report.py`, `tests/test_validate_ml_benchmark_execution_matrix.py`, `tests/test_validate_ml_agent_rush_benchmark_execution_packet.py` |
| Agent-side ML evidence | `tests/test_validate_ml_win_template_probe.py`, `tests/test_validate_ml3_agent_production_gap_audit.py`, `tests/test_validate_ml_wave2_ml2_ml3_readiness.py` |
| Pipeline and holdout gates | `tests/test_validate_ml_dvc_pipeline.py`, `tests/test_validate_ml_replay_holdout_outcomes.py`, `tests/test_validate_ml_wave3_ml5_readiness.py`, `tests/test_validate_ml_wave3_ml6_readiness.py` |

## Publication Rules

- Keep Python entry points under `scripts/` and pytest modules under `tests/`;
  do not add new loose `.py` files at repository root.
- Put durable fixtures under `fixtures/`, repeatable execution profiles under
  `profiles/`, roadmap shards under `roadmaps/`, and schemas under `schemas/`.
- Do not commit generated `runs/`, `generated/`, cache, bytecode, secrets, raw
  samples, malware, or model weights.
- Version curated benchmark artifacts only through the monorepo mirror manifest.
