# Tamandua ML Training Pipeline Roadmap

This document is the operational roadmap for moving the Tamandua ML pipeline
from the current no-execution planning state to production-candidate evidence.
It summarizes the server-side Malware-SMELL path, the agent-side ONNX path,
dataset acquisition sources, vx-underground/InTheWild handling, benchmark
lanes, and the guarded execution order.

Authoritative generated evidence lives under `docs/benchmarks/runs/`. If this
document disagrees with generated JSON contracts, the generated contracts win.

## Current State

- The ML architecture is implemented, but the current checkpoint is not a
  production-quality detector.
- The current ML system is validation-ready coordination and smoke-scale
  implementation evidence only. ML-1..ML-6 production validation remains
  pending until the guarded evidence listed below exists and passes.
- The current goal remains incomplete:
  - `goal_complete=false`
  - `ready_for_completion_claim=false`
  - `goal_missing_requirements=9`
  - next requirement: `wave1_governed_acquisition`
  - next execution guard: `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`
- The prelab path validates coordination only. It must not acquire samples,
  publish manifests, train, export, infer, benchmark, or contact live services.
- Current 2026-06-21 Wave 1 gate state:
  - `docs/benchmarks/runs/20260621T-ml-wave1-guarded-run-command-packet-post-lab-root.json`
    reports `ready_for_guarded_wave1_acquisition=true` with `0` execution
    blockers.
  - `docs/benchmarks/runs/20260621T-ml-wave1-operator-go-no-go-summary-post-lab-root.json`
    reports `decision=go_for_guarded_wave1_acquisition`.
  - The guarded launcher
    `docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1`
    now validates and records the post-lab-root operator summary and guarded
    packet before it can run with `-Execute`.
  - The canonical transcript
    `docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json`
    is absent before the guarded run, which is the expected pre-run state.
  - `docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json`
    exists but is a no-execution receipt with
    `ready_for_manifest_publish=false`; it explicitly blocks on the missing
    external production manifest and missing successful acquisition transcript.
- Latest no-execution prelab sweep: `2026-06-18`, using
  `docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/ml_prelab_validation_launcher.ps1`
  with `TAMANDUA_ML_DATA_ROOT=D:\treant\tamandua_ml_lab`. It completed
  contract validation without acquisition, publication, training, inference,
  benchmarks, or live service calls.
- The prior failed Wave 1 acquisition transcript was archived out of the
  canonical evidence path. Current contracts treat the canonical transcript as
  missing before execution, not as proof of acquisition. A clean governed
  acquisition transcript is still required before manifest publication.
- Retry guidance is published in
  `docs/benchmarks/runs/20260618T-ml-wave1-retry-runbook.json` and
  `docs/benchmarks/runs/20260618T-ml-wave1-retry-runbook.md`. It records the
  prior `returncode=1`, repeated MalwareBazaar `403` responses, final counts of
  `malware=1003/10000` and `goodware=10000/10000`, and the guarded retry
  sequence.
- A metadata-only MalwareBazaar access probe is available at
  `apps/tamandua_ml/scripts/ml_malwarebazaar_metadata_probe.py`. By default it
  does not contact the network. Live metadata probing requires both
  `--live-probe` and `TAMANDUA_ALLOW_ML_METADATA_PROBE=1`; it calls only
  `get_recent` metadata and never downloads samples.
- Latest live metadata probe result: `2026-06-19T00:43:16Z`, guarded
  metadata-only `get_recent`, Auth-Key present, HTTP `403`, zero metadata
  records, downloads samples `false`. This keeps Wave 1 blocked until
  MalwareBazaar Auth-Key/IP/API access is fixed or a governed alternate malware
  source plan is approved.
- A no-execution alternate source plan is published at
  `docs/benchmarks/runs/20260618T-ml-wave1-alternate-source-plan.json`. It
  identifies VirusShare archive acquisition as the primary candidate fallback
  because `acquire_from_hashlist.py` still depends on the blocked MalwareBazaar
  API path, while VX InTheWild remains metadata-only holdout context.
- Initial VirusShare fallback wiring is present in
  `apps/tamandua_ml/scripts/download_production_dataset.py` behind
  `--use-virusshare-fallback`, `--virusshare-archive-range`, and
  `VIRUSSHARE_API_KEY`. The dry-run artifact
  `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-dry-run.json` records
  the configured fallback without contacting VirusShare or downloading samples.
- `apps/tamandua_ml/scripts/ml_virusshare_metadata_probe.py` can validate the
  public VirusShare archive hashlist path before fallback execution. It defaults
  to no-contact mode and requires `--live-probe` plus
  `TAMANDUA_ALLOW_ML_METADATA_PROBE=1` for live hashlist access.
  The latest artifact
  `docs/benchmarks/runs/20260618T-ml-virusshare-metadata-probe.json` records
  archive `00400`, live hashlist HTTP `200`, `65536` hashes,
  `uses_file_download_api=false`, and `downloads_samples=false`.
- `apps/tamandua_ml/scripts/ml_virusshare_fallback_readiness_probe.py` checks
  the no-execution fallback preconditions: external data root, VirusShare dry-run
  shape, successful hashlist probe, `VIRUSSHARE_API_KEY` presence, and all
  acquisition/download guards absent.
  Current artifact
  `docs/benchmarks/runs/20260620T-ml-virusshare-fallback-readiness-secret-hardened.json`
  reports the fallback still blocked. The prior failed real acquisition
  transcript is treated as supersedable retry evidence (`returncode=1`). The
  remaining blockers are missing `VIRUSSHARE_API_KEY` and the hardened
  placeholder check `virusshare_api_key_not_placeholder`.
- The no-execution command packet for the lab operator is
  `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-command-packet.json`.
  It must not be executed until `VIRUSSHARE_API_KEY` is available and the
  readiness probe reports `ready_for_guarded_virusshare_fallback=true`.
- The command packet consistency check is
  `apps/tamandua_ml/scripts/ml_virusshare_fallback_command_packet_check.py`,
  with current artifact
  `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-command-packet-check.json`.
  It currently passes and confirms that the packet matches readiness, dry-run,
  hashlist, guard, and placeholder-secret expectations without executing any
  acquisition step.
- The generated pre-lab launcher
  `docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/ml_prelab_validation_launcher.ps1`
  now reruns that command-packet check as part of the no-execution sweep, and
  `tools/detection_validation/validate_ml_contracts.py` fails the execution plan
  if the check step is removed.
- VirusShare fallback readiness, command-packet check, and transition audit now
  have dedicated schemas plus central validator flags:
  `--ml-virusshare-fallback-readiness`,
  `--ml-virusshare-fallback-command-packet-check`, and
  `--ml-virusshare-fallback-transition-audit`. The pre-lab contract coverage
  artifact requires those flags and the corresponding built-in invariants
  before reporting `complete=true`.
- The generated Wave 1 handoff now includes
  `docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_virusshare_fallback_readiness_launcher.ps1`.
  This launcher is no-execution only: it refuses acquisition guards, refreshes
  VirusShare fallback readiness and packet consistency, then prints the
  governed operator commands from the packet.
- The transition audit
  `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-transition-audit.json`
  records that the fallback transcript contract can bind to the VirusShare
  fallback command packet, but manifest publication is still blocked until a
  real fallback transcript exists and lab-run intake, acquisition receipt,
  manifest publish receipt, closure gate, and acceptance checklist are
  regenerated.
- The latest Wave 1 source decision artifact
  `docs/benchmarks/runs/20260620T-ml-wave1-source-decision-secret-hardened.json`
  consolidates the current no-execution route selection. It records
  MalwareBazaar as blocked by the latest metadata-only `403`, selects
  `virusshare_fallback`, marks VirusShare as waiting only for a real,
  non-placeholder `VIRUSSHARE_API_KEY`, and keeps VX InTheWild as
  `holdout_only` / not allowed for training.
- The next-action runner is now source-decision aware. Current artifact
  `docs/benchmarks/runs/20260620T-ml-next-action-virusshare-source-aware.json`
  selects package `ml_data_virusshare_fallback`, runs only the no-execution
  VirusShare fallback readiness launcher, keeps `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`
  absent, and redacts `VIRUSSHARE_API_KEY`. It reports no-real-acquisition
  evidence, uses the source-aware execution status with an external
  `TAMANDUA_ML_DATA_ROOT` snapshot, and remains blocked only on a real
  `VIRUSSHARE_API_KEY` for guarded execution.
- The execution status generator is now source-decision aware as well. Current
  artifact
  `docs/benchmarks/runs/20260620T-ml-execution-status-virusshare-source-aware.json`
  validates `jsonschema+built-in`, removes the stale MalwareBazaar secret
  requirement from the active Wave 1 route, keeps `VIRUSSHARE_API_KEY` redacted
  and missing, and keeps guarded execution blocked until a real non-placeholder
  `VIRUSSHARE_API_KEY` is present.
- Post-publication/secret-sanitization status is captured in
  `docs/benchmarks/runs/20260620T2310Z-ml-execution-status-after-secret-sanitization.json`,
  `docs/benchmarks/runs/20260620T2310Z-ml-platform-readiness-after-secret-sanitization.json`,
  and
  `docs/benchmarks/runs/20260620T2310Z-ml-mirror-publication-after-secret-sanitization.json`.
  All three validate `jsonschema+built-in`. They record that the detection
  validation mirror is published, the ML mirror is synced and locally committed
  but remains `hold_do_not_push`, and ML platform readiness remains blocked by
  the missing governed VirusShare secret and downstream ML-1..ML-6 evidence.
- Post-lab-root mirror publication evidence is captured in
  `docs/benchmarks/runs/20260621T-ml-mirror-publication-post-lab-root-sync.json`.
  It validates `jsonschema+built-in` and records the current split state after
  the allowed mirrors were pushed: 8/9 mirrors are clean and push-ready,
  `tamandua-ml` staging is clean at local snapshot `8219957` with 800 tracked
  files, the ML remote remains empty by policy, and publication remains
  `hold_do_not_push` because `manifest_hold_active` and
  `ml_experimental_release_gate_active` are still true.
- Post-guarded-packet mirror publication evidence is captured in
  `docs/benchmarks/runs/20260621T-ml-mirror-publication-post-guarded-packet-publish.json`.
  It validates `jsonschema+built-in` after publishing the refreshed detection
  validation mirror. `tamandua-detection-validation` is clean at local/remote
  snapshot `e1b313f`, `tamandua-ml` staging is clean at local snapshot
  `221ccdd` with 731 tracked files, the ML remote remains `empty`, and ML
  publication remains `hold_do_not_push` because `manifest_hold_active` and
  `ml_experimental_release_gate_active` are still true.
  Post-sync mirror verification: `deploy verify tamandua-detection-validation`
  is intentionally build-deferred, and `deploy verify tamandua-ml` passed the
  metadata/dry-run suite with `21 passed`.
- The current secret-readiness next-action artifact
  `docs/benchmarks/runs/20260620T2320Z-ml-next-action-secret-readiness.json`
  validates `jsonschema+built-in` and records a no-execution env-remediation
  action rather than invoking PowerShell or a guarded launcher while
  `TAMANDUA_ML_DATA_ROOT` / `VIRUSSHARE_API_KEY` are absent.
- The Wave 1 execution environment preflight is now source-aware:
  `docs/benchmarks/runs/20260604T-ml-wave1-execution-environment-preflight.json`
  validates `jsonschema+built-in` and currently reports `ready=true` for the
  governed MalwareBazaar acquisition packet: external data root configured and
  outside the repo, sufficient capacity, `TAMANDUA_MALWAREBAZAAR_AUTH_KEY`
  present, VX archive download guard absent, and the canonical transcript
  missing before run. The separate source-decision evidence still records
  `virusshare_fallback` as the preferred fallback route if MalwareBazaar access
  fails again.
- Wave 1 post-acquisition intake is now compatible with both governed
  acquisition launchers: the original MalwareBazaar path and the
  `wave_1_virusshare_fallback_acquisition_launcher.ps1` path selected by the
  current source decision. Current artifact
  `docs/benchmarks/runs/20260620T-ml-wave1-lab-run-intake-virusshare-compatible.json`
  records that the intake still blocks until a successful guarded fallback
  transcript, a matching external production manifest, and green packet
  consistency evidence exist.
- The current post-MalwareBazaar-403 route authority is
  `docs/benchmarks/runs/20260621T-ml-wave1-source-decision-post-malwarebazaar-403.json`.
  It validates `jsonschema+built-in`, records the latest MalwareBazaar metadata
  probe as blocked by HTTP `403`, selects `virusshare_fallback`, and marks the
  route as `waiting_for_usable_virusshare_secret`.
- The current next-action run is
  `docs/benchmarks/runs/20260621T-ml-next-action-post-malwarebazaar-403-virusshare-lab-root.run.json`.
  It validates `jsonschema+built-in`, selects package
  `ml_data_virusshare_fallback`, records action `set_required_env`, preserves
  `env=VIRUSSHARE_API_KEY`, and emits
  `blocked:set_required_env:VIRUSSHARE_API_KEY`. It does not invoke PowerShell,
  acquire samples, train, export, infer, benchmark, or contact live services.
- The current next-gate authorization packet is
  `docs/benchmarks/runs/20260621T-ml-next-gate-authorization-post-malwarebazaar-403-virusshare-lab-root.json`.
  It validates `jsonschema+built-in`, selects `set_required_env`, records
  `authorized_for_guarded_execution=false`, and exposes no guarded launcher
  commands while the VirusShare secret is missing. The previous
  `post-win-template-gate-threading-governed` MalwareBazaar packet is retained
  as historical evidence, not the current route authority.
- The current compact operator packet for this gate is
  `docs/benchmarks/runs/20260621T-ml-next-operator-post-malwarebazaar-403-virusshare-lab-root-packet.json`
  with markdown at
  `docs/benchmarks/runs/20260621T-ml-next-operator-post-malwarebazaar-403-virusshare-lab-root-packet.md`.
  It validates `jsonschema+built-in`, exposes only env-remediation commands,
  renders no guarded launcher, redacts `VIRUSSHARE_API_KEY`, keeps VX archive
  downloads unauthorized, and records the ML mirror publication decision as
  `hold_do_not_push`.
- Latest ML-2/ML-3 agent parity readiness:
  `docs/benchmarks/runs/20260620T-ml-wave2-ml2-ml3-readiness-post-secret-hardening.json`.
  It is still blocked because ML-1 has not produced the candidate benchmark
  report, ONNX model, ONNX metadata, or model contract. The local agent parity
  toolchain itself is ready: Rust `1.96.0`, `onnxruntime.dll` present, minimum
  ONNX Runtime requirement met, launcher present, external data root outside
  the repo, and all required parity input files present.
- Latest ML-2/ML-3 operator go/no-go with agent smoke context:
  `docs/benchmarks/runs/20260620T1905Z-ml-wave2-ml2-ml3-agent-smoke-context-go-no-go.json`.
  It now validates `jsonschema+built-in` against the central contract, covering
  the post-secret-hardening readiness plus
  `docs/benchmarks/runs/20260620T-ml3-agent-parity-with-win-template.json`,
  keeps the production decision `no_go`, and records that agent smoke evidence
  is present, valid, quality-gate passing, and WIN-TEMPLATE attached, but
  `agent_smoke_evidence_unblocks_production=false`.
- Latest ML-2/ML-3 operator go/no-go consuming the ML-1 packet readiness:
  `docs/benchmarks/runs/20260620T2115Z-ml-wave2-ml2-ml3-agent-smoke-ml1-packets-go-no-go.json`.
  It validates `jsonschema+built-in`, consumes
  `20260620T2105Z-ml-wave2-ml2-ml3-readiness-ml1-packets.json`, keeps
  `decision=no_go`, preserves the WIN-TEMPLATE smoke evidence as context only,
  and keeps `agent_smoke_evidence_unblocks_production=false`.
- Latest ML-5 replay readiness consuming the ML-2/ML-3 packet readiness:
  `docs/benchmarks/runs/20260620T2125Z-ml-wave3-ml5-readiness-ml2-ml3-packets.json`.
  It validates `jsonschema+built-in`, consumes
  `20260620T2105Z-ml-wave2-ml2-ml3-readiness-ml1-packets.json`, keeps
  `ready_for_ml5_pipeline_replay=false`, and remains blocked by ML-2/ML-3
  parity, ML-4 service readiness, missing ML-1 model outputs, missing
  production ML-3/ML-4 reports, and missing ML-5 replay outcomes. It records
  the WIN-TEMPLATE smoke evidence as present and valid, but still requires the
  canonical `ml-prod-candidate-v1-ml3-agent-parity.json` before replay can be
  considered production-ready.
- Latest ML-5 operator go/no-go consuming the ML-5 packet readiness:
  `docs/benchmarks/runs/20260620T2127Z-ml-wave3-ml5-readiness-ml2-ml3-packets-go-no-go.json`.
  It validates `jsonschema+built-in`, consumes
  `20260620T2125Z-ml-wave3-ml5-readiness-ml2-ml3-packets.json`, keeps
  `decision=no_go`, preserves the pipeline replay guard
  `TAMANDUA_ALLOW_ML_PIPELINE_REPLAY`, and does not set guards, build fixtures,
  run replay, run inference, or contact live services.
- Latest ML-6 holdout readiness consuming the ML-5 packet readiness:
  `docs/benchmarks/runs/20260620T2135Z-ml-wave3-ml6-readiness-ml5-packets.json`.
  It validates `jsonschema+built-in`, consumes
  `20260620T2125Z-ml-wave3-ml5-readiness-ml2-ml3-packets.json`, keeps
  `ready_for_ml6_holdout=false`, and remains blocked by ML-5 replay readiness,
  ML-1 candidate readiness, missing ML-1 benchmark/model artifacts, missing
  `TAMANDUA_ML_TRAINING_CUTOFF`, and missing ML-6 holdout prediction outcomes.
  The execution step remains guarded by `TAMANDUA_ALLOW_ML_HOLDOUT`; this
  readiness packet does not build fixtures, run holdout benchmarks, train
  models, run inference, or contact live services.
- Latest ML-6 operator go/no-go consuming the ML-6 packet readiness:
  `docs/benchmarks/runs/20260620T2145Z-ml-wave3-ml6-readiness-ml5-packets-go-no-go.json`.
  It validates `jsonschema+built-in`, consumes
  `20260620T2135Z-ml-wave3-ml6-readiness-ml5-packets.json`, keeps
  `decision=no_go`, preserves the holdout guard
  `TAMANDUA_ALLOW_ML_HOLDOUT`, requires the cutoff env
  `TAMANDUA_ML_TRAINING_CUTOFF`, and does not set guards or execute holdout
  benchmarks.
- Latest benchmark unblock validation status with central contract packet
  coverage:
  `docs/benchmarks/runs/20260620T1935Z-ml-benchmark-unblock-validation-status-contract-packets.json`.
  It validates `jsonschema+built-in`, confirms all three control packets are
  centrally valid (`20260620T2345Z` secret-readiness next-gate,
  `20260620T2355Z` secret-readiness next-operator, and ML-2/ML-3 agent-smoke
  go/no-go), keeps `next_operator_publication_decision=hold_do_not_push`,
  records `next_operator_blocker_count=4`, and records
  `ml2_ml3_agent_smoke_unblocks_production=false`. It still reports all 40
  benchmark unblock items as pending.
- Latest benchmark unblock validation status consistency:
  `docs/benchmarks/runs/20260620T1945Z-ml-benchmark-unblock-validation-status-consistency-contract-packets.json`.
  It validates `jsonschema+built-in`, reports `consistent=true`, confirms the
  status still matches the canonical queue and handoff consistency artifact,
  and preserves the same contract-packet coverage fields without converting
  smoke evidence into production readiness.
- Latest benchmark lane rollup with contract packet coverage:
  `docs/benchmarks/runs/20260620T1955Z-ml-benchmark-lane-rollup-contract-packets.json`.
  It validates `jsonschema+built-in`, consumes the packet-covered status and
  consistency artifacts, keeps `total_pending_items=40`, and preserves
  `next_operator_publication_decision=hold_do_not_push`.
- Latest benchmark critical path with contract packet coverage:
  `docs/benchmarks/runs/20260620T2005Z-ml-benchmark-critical-path-contract-packets.json`.
  It validates `jsonschema+built-in`, consumes the packet-covered lane rollup
  and status artifacts, covers all 40 pending items across 22 ordered blocker
  steps, and still starts at `01-wave1-manifest-publication`.
- Latest benchmark critical path handoff bundle with contract packet coverage:
  `docs/benchmarks/runs/20260620T2015Z-ml-benchmark-critical-path-handoff-bundle-contract-packets.json`.
  It validates `jsonschema+built-in`, consumes the packet-covered critical
  path, writes 22 no-execution per-step handoff files under
  `docs/benchmarks/runs/20260620T2015Z-ml-benchmark-critical-path-contract-packets.handoff/`,
  and preserves validation-only commands for blocker resolution.
- Latest benchmark critical path handoff consistency with contract packet
  coverage:
  `docs/benchmarks/runs/20260620T2025Z-ml-benchmark-critical-path-handoff-consistency-contract-packets.json`.
  It validates `jsonschema+built-in`, reports `consistent=true`, confirms the
  packet-covered handoff bundle still matches the packet-covered critical path,
  and does not convert coordination handoffs into production benchmark evidence.
- Latest benchmark actionability audit with contract packet coverage:
  `docs/benchmarks/runs/20260620T2035Z-ml-benchmark-actionability-audit-contract-packets.json`.
  It validates `jsonschema+built-in`, consumes the packet-covered critical path,
  handoff bundle, and handoff consistency artifacts, reports
  `actionable=true` with 40/40 queue items, 22/22 critical-path steps, and 22/22
  handoff files exposing validation-only resolution commands, and keeps
  `evidence_usable_for_goal=0`.
- Latest execution master handoff with actionability packet coverage:
  `docs/benchmarks/runs/20260620T2045Z-ml-execution-master-handoff-actionability-packets.json`.
  It validates `jsonschema+built-in`, consumes the packet-covered benchmark
  critical path and actionability audit, carries `benchmark_actionability_ready=true`
  with `benchmark_actionability_gap_count=0`, and remains blocked with
  `ready_for_lab_operator=false` because Wave 1 lab execution is still not proven.
- Latest Wave 2 ML-1 readiness with master-handoff packet coverage:
  `docs/benchmarks/runs/20260620T2055Z-ml-wave2-ml1-readiness-master-packets.json`.
  It validates `jsonschema+built-in`, consumes the actionability-packet master
  handoff, keeps `ready_for_ml1_candidate=false`, and preserves blockers
  `ml_execution_master_handoff_not_ready`,
  `manifest_publish_receipt_incomplete`, and
  `missing_canonical_dataset_manifest`.
- Latest ML-2/ML-3 readiness consuming the ML-1 master packet:
  `docs/benchmarks/runs/20260620T2105Z-ml-wave2-ml2-ml3-readiness-ml1-packets.json`.
  It validates `jsonschema+built-in`, consumes
  `20260620T2055Z-ml-wave2-ml1-readiness-master-packets.json`, and keeps
  `ready_for_ml2_ml3_parity=false`. The local agent parity toolchain remains
  ready (`rustc 1.96.0`, ONNX Runtime DLL present, launcher present, and 5/5
  required parity inputs present), but the production gate stays blocked by
  `wave2_ml1_readiness_blocked`, `missing_ml1_benchmark_report`,
  `missing_candidate_onnx_model`, `missing_candidate_onnx_metadata`, and
  `missing_ml1_model_contract`.
- Latest ML-3 agent-side evidence:
  `docs/benchmarks/runs/20260620T-ml3-agent-parity-with-win-template.json`.
  This report validates `jsonschema+built-in`, is explicitly scoped as
  `ml-smoke-fixture-v1`, and records Rust agent ONNX parity on the frozen
  6-sample synthetic fixture with verdict agreement `1.0` and max absolute
  probability delta `0.000027954578` against tolerance `0.0001`. It also
  attaches
  `docs/benchmarks/runs/20260619T-win-template-ml-probe.json`, where local
  checkpoint inference on deterministic WIN-TEMPLATE fixtures completed without
  endpoint contact: 3 fixtures were scored benign and the seeded high-entropy
  control was scored malicious. This is useful agent-side detection evidence,
  but not a production malware benchmark, not endpoint telemetry evidence, and
  it does not unblock ML-1, Wave 1 acquisition, or ML-5 replay by itself. The
  ML-3 report generator now fails `ml-prod-candidate-v1` reports unless the
  fixture, ONNX model, metadata, or model contract identity includes
  `ml-prod-candidate-v1`, preventing smoke evidence from satisfying the
  canonical candidate gate.
- Latest rerun of the Rust agent ONNX smoke path:
  `docs/benchmarks/ML_AGENT_ONNX_PARITY_SMOKE_20260621.md`.
  The rerun executed the Rust fixture contract test, the fixture CLI, the
  `ml_agent_onnx_parity` binary with `--features onnx`, regenerated an ML-3
  smoke report, and validated it through `validate_ml_contracts.py`. Result:
  quality gate `pass`, 6/6 verdict matches, verdict agreement `1.0`, max
  absolute probability delta `0.000027954578` against tolerance `0.0001`.
  This strengthens confidence in the agent ONNX path but remains
  `ml-smoke-fixture-v1` evidence only; it does not satisfy the
  `ml-prod-candidate-v1` ML-3 production gate.
- Historical ML-5 readiness smoke-context packet:
  `docs/benchmarks/runs/20260604T-ml-wave3-ml5-readiness-probe.json`.
  The report records `ml3_agent_side_evidence_present=true`,
  `ml3_agent_side_evidence_valid=true`,
  `ml3_agent_side_evidence_quality_gate_passed=true`, sample count `6`, and
  `ml3_agent_side_evidence_win_template_attached=true`. It still keeps
  `ready_for_ml5_pipeline_replay=false` and retains
  `missing_ml3_agent_parity_report` because the canonical production-candidate
  report `ml-prod-candidate-v1-ml3-agent-parity.json` is still absent.
- Latest consolidated platform audit consuming the packet-covered ML lanes:
  `docs/benchmarks/runs/20260620T2155Z-ml-platform-readiness-ml6-packets.json`.
  It validates `jsonschema+built-in`, consumes the ML-1 `2055Z`,
  ML-2/ML-3 `2105Z`, ML-5 `2125Z`, and ML-6 `2135Z` readiness packets, and
  remains blocked with `production_candidate_ready=false`, completion
  `partial_evidence`, proven `1/10`, missing `9`, and next unproven
  requirement `wave1_governed_acquisition`.
- The only usable goal evidence today is the public claim boundary guard.

Primary current artifacts:

- `docs/benchmarks/runs/20260604T-ml-goal-snapshot.json`
- `docs/benchmarks/runs/20260604T-ml-execution-master-handoff.json`
- `docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json`
- `docs/benchmarks/runs/ml-prod-candidate-v1-acquisition-dry-run.json`
- `docs/benchmarks/runs/ml-vx-inthewild-inventory.json`
- `docs/benchmarks/runs/20260618T-ml-wave1-retry-runbook.json`
- `docs/benchmarks/runs/20260618T-ml-wave1-alternate-source-plan.json`
- `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-dry-run.json`
- `docs/benchmarks/runs/20260618T-ml-virusshare-metadata-probe.json`
- `docs/benchmarks/runs/20260620T-ml-virusshare-fallback-readiness-secret-hardened.json`
- `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-command-packet.json`
- `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-command-packet-check.json`
- `docs/benchmarks/runs/20260618T-ml-virusshare-fallback-transition-audit.json`
- `docs/benchmarks/runs/20260620T-ml-wave1-source-decision-secret-hardened.json`
- `docs/benchmarks/runs/20260620T-ml-execution-status-virusshare-source-aware.json`
- `docs/benchmarks/runs/20260620T-ml-next-action-virusshare-source-aware.json`
- `docs/benchmarks/runs/20260620T-ml-wave1-lab-run-intake-virusshare-compatible.json`
- `docs/benchmarks/runs/20260620T1615Z-ml-next-gate-authorization-virusshare-source-aware.json`
- `docs/benchmarks/runs/20260620T1840Z-ml-next-operator-virusshare-packet.json`
- `docs/benchmarks/runs/20260620T-ml-wave2-ml2-ml3-readiness-post-secret-hardening.json`
- `docs/benchmarks/runs/20260620T1905Z-ml-wave2-ml2-ml3-agent-smoke-context-go-no-go.json`
- `docs/benchmarks/runs/20260620T2155Z-ml-platform-readiness-ml6-packets.json`
- `docs/benchmarks/runs/20260620T1600Z-ml-mirror-publication-virusshare-transcript-intake.json`
- `docs/benchmarks/runs/20260620T1625Z-ml-mirror-publication-source-aware-authorization.json`
- `docs/benchmarks/runs/20260620T1825Z-ml-mirror-publication-after-local-ml-hold-commit.json`
- `docs/benchmarks/runs/20260620T1850Z-ml-mirror-publication-after-operator-packet-local-ml-commit.json`
- `docs/benchmarks/runs/20260620T1915Z-ml-mirror-publication-after-agent-smoke-context-local-ml-commit.json`
- `docs/benchmarks/runs/20260620T1935Z-ml-benchmark-unblock-validation-status-contract-packets.json`
- `docs/benchmarks/runs/20260620T1945Z-ml-benchmark-unblock-validation-status-consistency-contract-packets.json`
- `docs/benchmarks/runs/20260620T1955Z-ml-benchmark-lane-rollup-contract-packets.json`
- `docs/benchmarks/runs/20260620T2005Z-ml-benchmark-critical-path-contract-packets.json`
- `docs/benchmarks/runs/20260620T2015Z-ml-benchmark-critical-path-handoff-bundle-contract-packets.json`
- `docs/benchmarks/runs/20260620T2025Z-ml-benchmark-critical-path-handoff-consistency-contract-packets.json`
- `docs/benchmarks/runs/20260620T2035Z-ml-benchmark-actionability-audit-contract-packets.json`
- `docs/benchmarks/runs/20260620T2045Z-ml-execution-master-handoff-actionability-packets.json`
- `docs/benchmarks/runs/20260620T2055Z-ml-wave2-ml1-readiness-master-packets.json`
- `docs/benchmarks/runs/20260620T2105Z-ml-wave2-ml2-ml3-readiness-ml1-packets.json`
- `docs/benchmarks/runs/20260620T2115Z-ml-wave2-ml2-ml3-agent-smoke-ml1-packets-go-no-go.json`
- `docs/benchmarks/runs/20260620T2125Z-ml-wave3-ml5-readiness-ml2-ml3-packets.json`
- `docs/benchmarks/runs/20260620T2127Z-ml-wave3-ml5-readiness-ml2-ml3-packets-go-no-go.json`
- `docs/benchmarks/runs/20260620T2135Z-ml-wave3-ml6-readiness-ml5-packets.json`
- `docs/benchmarks/runs/20260620T2145Z-ml-wave3-ml6-readiness-ml5-packets-go-no-go.json`

Superseded mirror publication audit after the packet-plan refresh:

- Current audit:
  `docs/benchmarks/runs/20260620T2250Z-ml-mirror-publication-after-packet-plan-refresh.json`.

- This block is historical. The current mirror authority is the latest
  `ml_mirror_publication_audit` artifact under `docs/benchmarks/runs/`.
- `tamandua-agent` and `tamandua-server` were clean and had remote content at
  the time of this older audit.
- `tamandua-ml` remains intentionally unpublished with remote state `empty`,
  local head `d0c303b`, `hold=true`, and publication decision
  `hold_do_not_push`.
- Historical ML publication blockers were `manifest_hold_active` and
  `ml_experimental_release_gate_active`.
- The compact operator packet
  `docs/benchmarks/runs/20260620T2355Z-ml-next-operator-secret-readiness-packet.json`
  restated the same release decision for handoff/CI consumption:
  `ready_for_guarded_execution=false`, blockers
  `virusshare_api_key_present`, `virusshare_api_key_not_placeholder`,
  `missing_env:TAMANDUA_ML_DATA_ROOT`, and `missing_env:VIRUSSHARE_API_KEY`,
  and `publication_decision=hold_do_not_push`.
- The current operator packet has superseded those source-secret blockers with
  governed MalwareBazaar acquisition readiness. The release decision remains
  `hold_do_not_push`.
- The next action remains: keep the ML mirror on hold until the experimental
  release gate clears via production-candidate evidence, not merely source-code
  readiness.

Latest benchmark unblock validation after the mirror publication pass:

- All 40 ML benchmark unblock items remain pending.
- Pending categories: 7 dependency, 22 artifact, 2 environment, and 9 other.
- Unknown evidence targets are now 0; 38 items map to explicit evidence paths
  and the status lists 71 expected evidence file references for operator
  follow-up.
- Contract packet coverage is green for no-execution coordination:
  `contract_packets_validated=3`,
  `contract_packets_all_validated=true`,
  `next_operator_publication_decision=hold_do_not_push`, and
  `ml2_ml3_agent_smoke_unblocks_production=false`.
- The matching consistency artifact is green:
  `consistent=true`, `check_count=14`, and
  `status_preserves_contract_packet_coverage=true`.
- The lane rollup is refreshed against those artifacts and remains
  `total_pending_items=40`; no lane is promoted by smoke evidence alone.
- The critical path is refreshed against that rollup and still covers all 40
  pending items in 22 steps, with first phase
  `01-wave1-manifest-publication`.
- The next unproven requirement is still `wave1_governed_acquisition`.
- The next guarded execution env remains `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`.
- This status is no-execution evidence only; it does not run acquisition,
  training, inference, benchmarks, or live services.

Latest post-403 VirusShare fallback operator-route and mirror hold refresh:

- Current mirror state is captured by the latest `ml_mirror_publication_audit`
  artifact under `docs/benchmarks/runs/`.
- `tamandua-server` and `tamandua-detection-validation` are published and clean
  in that audit.
- `tamandua-ml` is clean locally, remote remains `empty`, and publication
  remains `hold_do_not_push`.
- Most recent mirror publication state at this roadmap refresh:
  `tamandua-detection-validation` is published at
  `7a5b15e Update-ML-fallback-validation-contracts`; `tamandua-ml` is staged
  locally at `16d7c84 Stage-post-403-VirusShare-fallback-gate` and remains
  HOLD with remote `empty`.
- The refreshed Wave 1 post-lab-root guarded packet is now the command source
  of truth for acquisition:
  `docs/benchmarks/runs/20260621T-ml-wave1-guarded-run-command-packet-post-lab-root.json`.
  The matching operator go/no-go is
  `docs/benchmarks/runs/20260621T-ml-wave1-operator-go-no-go-summary-post-lab-root.json`.
- The ML-2/ML-3 operator go/no-go now consumes
  `docs/benchmarks/runs/20260621T-ml3-agent-parity-with-win-template-local-inference.json`
  and propagates WIN-TEMPLATE false-positive context into ML-5/ML-6/platform
  readiness.
- The safe synthetic WIN-TEMPLATE probe scored 4 fixtures as 3 benign and 1
  malicious. The malicious safe fixture is
  `win_template_seeded_high_entropy_control`, recorded as a false-positive
  candidate with `production_gate_impact=no_go_for_detection_claims`.
- Mirror validation evidence: detection-validation `83 passed, 1 skipped`; ML
  mirror focused validation `38 passed, 3 skipped`; `deploy verify tamandua-ml`
  passed its metadata/dry-run suite.
- The refreshed benchmark unblock chain is now:
  `20260621T-ml-benchmark-unblock-queue-post-win-template-gate-threading.json`,
  `20260621T-ml-benchmark-unblock-validation-status-post-win-template-gate-threading.json`,
  and
  `20260621T-ml-benchmark-unblock-validation-status-consistency-post-win-template-gate-threading.json`.
  It is consistent with 40 pending items, 0 resolved items, 0 unknown evidence
  targets, 14/14 consistency checks passing,
  `next_operator_ready_for_guarded_execution=true`,
  `next_operator_blocker_count=0`, and
  `next_operator_publication_decision=hold_do_not_push`.
- The current next-gate/operator packets are
  `20260621T-ml-next-gate-authorization-post-malwarebazaar-403-virusshare-lab-root.json`
  and
  `20260621T-ml-next-operator-post-malwarebazaar-403-virusshare-lab-root-packet.json`.
- The operator packet now selects the VirusShare fallback env-remediation route
  with `effective_source_route=virusshare_fallback`,
  `source_auth.env=VIRUSSHARE_API_KEY`, `authorized_for_guarded_execution=false`,
  and blockers `virusshare_api_key_present`,
  `virusshare_api_key_not_placeholder`, `missing_env:TAMANDUA_ML_DATA_ROOT`,
  and `missing_env:VIRUSSHARE_API_KEY`. This means the next concrete action is
  setting a real, non-placeholder `VIRUSSHARE_API_KEY` in the isolated lab and
  rerunning status/readiness/authorization, not launching acquisition yet.
- The next unproven requirement remains `wave1_governed_acquisition`; the next
  guarded execution env remains `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`.

## Architecture

Server-side implementation:

- Location: `apps/tamandua_ml/`
- Model family: Malware-SMELL
- Encoder: VGG-19 pretrained weights plus a fully connected projection head
- Input transform: binary bytes to 64x64 grayscale image
- S-space: absolute distance plus Cauchy kernel with similarity and
  dissimilarity markers
- Classifier: KNN over S-space embeddings
- Training loss: contrastive loss plus S-space cross-entropy
- API surface: predict, batch predict, transformer predict, model info, reload

Agent-side implementation:

- Location: `apps/tamandua_agent/src/ml/`
- ONNX runtime feature gates: `onnx` and `ml-local`
- Runtime path: dynamic ONNX Runtime loading
- Model transport: chunked TAMC format with SHA256 per chunk
- Loading strategy: streaming loader plus LRU layer cache
- Export path: `apps/tamandua_ml/scripts/export_onnx.py`
- Optional compression: dynamic INT8 quantization

## Model Component Status (verified reality)

This section records the verified production status of each model component so
the roadmap does not overstate what is wired. For full external-model detail see
`docs/benchmarks/EXTERNAL_MODELS_INTEGRATION.md`.

Production ensemble:

- The production ensemble is instantiated in
  `apps/tamandua_ml/src/api/server.py` (~lines 265-285) with **only**
  `{smell, transformer}`.
- `ensemble.py` contains `malconv2` and `ember` adapter branches
  (`model_type` dispatch ~lines 73-76, `_NAME_TYPE_MAP` ~lines 202-207), but
  nothing in production instantiates the ensemble with them. They are
  **adapter-capable but production-unused.**

External models (summary; detail in EXTERNAL_MODELS_INTEGRATION.md):

- **MalConv2** — adapter present, production-unused. **Decision:** stays OUT of
  the production ensemble until an explicit FP budget justifies it; dormant
  adapter branches fenced as experimental. Validation: 38% recall on a 13-sample
  Wave 1 set (concept-drift baseline).
- **EMBER** — booster loads; `predict_features(vec)` works; raw-byte `predict()`
  still **BLOCKED** at sklearn string-feature extraction despite numpy/sklearn
  shims landed 2026-06-08 (see
  `docs/benchmarks/runs/20260608T-ember-e2e-postmortem.md`). Work is **FROZEN**.
- **AVCLASS** — `avclass_normalizer.py` works (avclass-malicialab 2.8.10). Not
  yet wired into `acquire_malware_bazaar.py` (~line 471); wiring **in progress**.
  ROI is **zero** until a retraining loop over field/production telemetry
  exists — **hygiene, not a product deliverable.**

Sequence / behavioral models:

- `encoder.py` + `sequence.py` APIs exist, but the classifier checkpoints
  `lstm_best.pt` / `transformer_best.pt` **DO NOT EXIST** (heads untrained), and
  the Elixir backend **never** calls `/sequence/predict` (zero hits across
  `tamandua_server`). Status: **ORPHANED.**
- `apps/tamandua_ml/models/encoder.pt` (112 MB) is unreferenced in production
  code, but it is the designated input for a pending **one-day ablation
  experiment** (logistic regression on encoder features vs the existing
  deterministic detection score, on a leakage-controlled holdout) that would
  decide whether the behavioral-ML path has signal. Status: **reserved for
  ablation, NOT dead.** The ablation is **gated** on first verifying schema
  compatibility between `encoder.pt`'s training feature schema and the telemetry
  production emits today.

Outstanding tasks (external / behavioral path):

- **MalConv2 ensemble integration is no longer an open task** — it is a
  deliberate exclusion (adapter present, production intentionally omits it).
- **EMBER raw-byte unblock is FROZEN / deprioritized** — do not invest until a
  named customer / clear need justifies it.
- **AVCLASS wiring is IN PROGRESS** — hygiene only, with the ROI-zero caveat
  (no value until a committed retraining loop exists).
- **Sequence path requires the schema-compatibility check + ablation BEFORE any
  training investment** — heads are untrained and the path is orphaned today.

## Dataset Sources

Production-candidate training starts with MalwareBazaar plus goodware. Other
sources are enrichment, historical coverage, or holdout context until their
governance gates are explicitly cleared.

| Source | Script | Current role |
| --- | --- | --- |
| MalwareBazaar | `acquire_malware_bazaar.py` | Primary malware acquisition; requires `TAMANDUA_MALWAREBAZAAR_AUTH_KEY` / `Auth-Key` |
| MalwareBazaar metadata probe | `ml_malwarebazaar_metadata_probe.py` | Optional no-download access check before retrying Wave 1 |
| MalwareBazaar hashlist | `acquire_from_hashlist.py` | Resume path after MalwareBazaar access is fixed; currently blocked by the same API access issue |
| System goodware | `acquire_goodware.py` | Primary benign acquisition |
| VirusTotal v3 | `acquire_virustotal.py` | Optional enrichment and label validation |
| HybridAnalysis | `acquire_hybrid_analysis.py` | Optional behavioral enrichment |
| VirusShare | `acquire_virusshare.py` + `download_production_dataset.py --use-virusshare-fallback` | Historical malware source; primary fallback candidate while MalwareBazaar returns 403 |
| Malimg | `download_malimg.py` | Academic image-family baseline |
| MaleVis | `download_malevis.py` | Academic baseline / fallback fixture |
| EMBER | `download_dataset.py` | PE feature baseline, not raw-image equivalent |
| vx-underground InTheWild | `acquire_vx_underground.py` | Holdout candidate metadata only |

## vx-underground / InTheWild Policy

The InTheWild collection is useful for temporal holdout and cross-time
robustness, but it is not part of the current train/validation/test split.

Current integrated behavior:

- `acquire_vx_underground.py` defaults to inventory-only mode.
- The inventory artifact is
  `docs/benchmarks/runs/ml-vx-inthewild-inventory.json`.
- The inventory is metadata only:
  - `archive_downloaded=false`
  - `inventory_role=holdout_candidate`
  - `holdout_role=holdout_metadata_only`
  - `used_in_training=false`
  - `raw_archives_in_repo=false`
  - `archive_extraction_performed=false`
  - `operator_next_command` is an inventory refresh command only; it does not
    include `--download`, credentials, tokens, or API keys.
- `download_production_dataset.py --dry-run --vx-inventory ...` may reference
  the inventory as holdout context.
- VX samples are not allowed in training splits until extraction, dedup,
  enrichment, and approval gates exist and pass.

Guard boundary:

- `TAMANDUA_ALLOW_ML_REAL_ACQUISITION` authorizes the governed production
  acquisition launcher.
- `TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH` authorizes sanitized manifest
  publication after governed acquisition evidence exists.
- `TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD` authorizes VX archive download only.
- These are separate guards. A Wave 1 dry-run or production acquisition plan
  must keep `TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD` unset.

The current inventory is browser-observed after automated fetch returned HTTP
403. A 2026-06-18 inventory-only recheck with
`apps/tamandua_ml/scripts/acquire_vx_underground.py` confirmed the same HTTP 403
boundary and did not download archives. The checked-in inventory records a
partial listing of `InTheWild.0151.7z` through `InTheWild.0161.7z`, with archive
sizes around 29-34 GB each. That is enough for planning holdout capacity, not
enough to claim sample availability.

## Execution Waves

The generated master handoff defines the current execution order.

1. Wave 1: governed acquisition and sanitized manifest publication
   - current governed validation launcher:
     `docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1`
   - current guarded governed execute launcher:
     `docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1 -Execute`
   - VirusShare fallback launchers remain conditional fallback evidence only;
     they are not selected by the current post-WIN-TEMPLATE operator packet.
   - guard: `TAMANDUA_ALLOW_ML_REAL_ACQUISITION`
   - post-acquisition publish guard: `TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH`
   - required evidence:
     - real acquisition transcript
     - acquisition receipt
     - manifest publish receipt
     - acceptance checklist
     - canonical sanitized dataset manifest

2. Wave 2 / ML-1: isolated model quality and model card
   - guard: `TAMANDUA_ALLOW_ML_TRAINING`
   - produces candidate quality report, model contract, model card, and ONNX
     export prerequisites

3. Wave 2 / ML-2 and ML-3: PyTorch/ONNX parity and agent parity
   - guard: `TAMANDUA_ALLOW_ML_PARITY`
   - proves server-side parity and agent-side ONNX behavior

4. Wave 2 / ML-4: live service benchmark
   - guard: `TAMANDUA_ALLOW_ML_SERVICE_BENCH`
   - requires service auth and live service readiness

5. Wave 3 / ML-5: full Tamandua replay
   - guard: `TAMANDUA_ALLOW_ML_PIPELINE_REPLAY`
   - proves the model inside the Tamandua platform workflow

6. Wave 3 / ML-6: cross-time holdout
   - guard: `TAMANDUA_ALLOW_ML_HOLDOUT`
   - requires `TAMANDUA_ML_TRAINING_CUTOFF`
   - should use temporally separated data; vx-underground InTheWild is a
     candidate only after its own download/extraction/enrichment gates exist

## Benchmark Lanes

The benchmark plan must cover all three detection surfaces:

- standalone model detection
- agent-side ONNX detection
- Tamandua platform replay detection

Current benchmark coordination status:

- `benchmark_detection_surface_contract_ready=true`
- `standalone_detection_surface_covered=true`
- `agent_onnx_detection_surface_covered=true`
- `tamandua_detection_surface_covered=true`
- `critical_path_steps=22`
- `pending_items=40`
- `evidence_usable_for_goal=0`

This means the benchmark work is planned and actionable, but no benchmark
result is yet usable as production evidence.

## Completion Requirements

The goal cannot be marked complete until these evidence classes are present and
validated:

- Wave 1 governed acquisition transcript and receipt
- sanitized production dataset manifest
- ML-1 model quality report
- ML-1 model contract and model card
- ML-2 PyTorch versus ONNX parity report
- ML-3 agent-side ONNX parity report
- ML-4 live service benchmark report
- ML-5 full Tamandua replay report
- ML-6 cross-time holdout report

Current missing requirement ids:

- `wave1_governed_acquisition`
- `wave1_sanitized_manifest`
- `ml1_model_quality`
- `ml1_model_contract_and_card`
- `ml2_pytorch_onnx_parity`
- `ml3_agent_onnx_parity`
- `ml4_service_benchmark`
- `ml5_tamandua_replay`
- `ml6_cross_time_holdout`

## Next Operator Step

The next actionable step remains env-remediation only. Do not run the guarded
Wave 1 acquisition launcher until the VirusShare fallback readiness probe
reports `ready_for_guarded_virusshare_fallback=true` and a refreshed
authorization packet selects `launch_package`.

The current route authority is
`docs/benchmarks/runs/20260621T-ml-next-operator-post-malwarebazaar-403-virusshare-lab-root-packet.md`:
`virusshare_fallback`, `ready_for_guarded_execution=false`,
`authorized_for_guarded_execution=false`, `source_auth.env=VIRUSSHARE_API_KEY`,
and `publication_decision=hold_do_not_push`.

Optional MalwareBazaar metadata access check before the guarded retry:

```powershell
$env:TAMANDUA_ALLOW_ML_METADATA_PROBE='1'
python apps\tamandua_ml\scripts\ml_malwarebazaar_metadata_probe.py --live-probe
Remove-Item Env:TAMANDUA_ALLOW_ML_METADATA_PROBE -ErrorAction SilentlyContinue
```

This check is not Wave 1 evidence. It only proves whether the current
`TAMANDUA_MALWAREBAZAAR_AUTH_KEY` can reach `get_recent` metadata without
downloading sample bytes. Do not use it as a replacement for the guarded
operator packet or for the acquisition transcript.

Current env-remediation command:

```powershell
$env:TAMANDUA_ML_DATA_ROOT='D:\treant\tamandua_ml_lab_data'
$env:VIRUSSHARE_API_KEY='<from isolated lab secret store>'
powershell -NoProfile -File docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_virusshare_secret_ready_launcher.ps1
```

Validation-only fallback readiness command after env remediation:

```powershell
powershell -NoProfile -File docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_virusshare_fallback_readiness_launcher.ps1
powershell -NoProfile -File docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_virusshare_secret_ready_launcher.ps1
```

Guarded VirusShare fallback acquisition command, only after readiness is green
and only inside the isolated lab:

```powershell
$env:TAMANDUA_ML_DATA_ROOT='D:\treant\tamandua_ml_lab_data'
$env:VIRUSSHARE_API_KEY='<from isolated lab secret store>'
$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION='1'
powershell -NoProfile -File docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_virusshare_fallback_acquisition_launcher.ps1 -Execute
Remove-Item Env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION -ErrorAction SilentlyContinue
Remove-Item Env:VIRUSSHARE_API_KEY -ErrorAction SilentlyContinue
```

The fallback launcher validates readiness and command-packet consistency before
calling `download_production_dataset.py`; do not invoke the direct acquisition
script for production evidence outside the guarded launcher.

Do not set `TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD` during Wave 1 production
dataset acquisition. VX archive download is a separate approved operation.

Optional VX holdout metadata refresh, no credentials and no archive download:

```powershell
python apps\tamandua_ml\scripts\acquire_vx_underground.py --output docs\benchmarks\runs\20260604T-vx-inventory-smoke --inventory-out docs\benchmarks\runs\ml-vx-inthewild-inventory.json
```

Optional WIN-TEMPLATE local ML probe, no endpoint contact and no malware:

```powershell
python apps\tamandua_ml\scripts\win_template_ml_probe.py --run-local-inference --output docs\benchmarks\runs\20260619T-win-template-ml-probe.json
```

This probe uses deterministic Windows-shaped fixtures only. A completed report
shows local checkpoint behavior on fixtures, not a production detection
benchmark, endpoint telemetry claim, or malware benchmark.

Current ML-3 consolidated report with WIN-TEMPLATE probe attached:

```powershell
python apps\tamandua_ml\scripts\ml3_agent_parity_report.py --fixture docs\benchmarks\runs\20260604T174850Z-ml-agent-parity-fixture.json --cargo-output docs\benchmarks\runs\20260606T-ml3-agent-parity-fixture.log --agent-results docs\benchmarks\runs\20260606T-ml3-agent-parity-results.json --win-template-probe docs\benchmarks\runs\20260619T-win-template-ml-probe.json --output docs\benchmarks\runs\20260620T-ml3-agent-parity-with-win-template.json --markdown-output docs\benchmarks\runs\20260620T-ml3-agent-parity-with-win-template.md --report-id 20260620t-ml3-agent-parity-with-win-template --model-version ml-smoke-fixture-v1 --require-cargo-fixture-validation --claim-boundary "ML-3 smoke agent-side evidence with WIN-TEMPLATE context. This proves Rust ONNX parity only against the frozen synthetic fixture and does not satisfy the canonical ml-prod-candidate-v1 ML-3 gate."
```
