# ML Publication And Benchmark Handoff - 2026-06-21

Status: active handoff
Claim boundary: coordination and publication decision only. This document does
not claim that acquisition, training, inference, live service execution, or
Tamandua end-to-end benchmark execution has happened.
ML validation boundary: current ML artifacts are validation-ready only,
not production-trained, and production validation remains pending through the
ML-1..ML-6 gates.

## Current Decision

Do not publish the `tamandua-ml` public mirror yet.

The source mirror remains intentionally held because the current evidence shows
`production_candidate_ready=false`, `completion_state=partial_evidence`, and the
next unproven requirement is `wave1_governed_acquisition`. The source mirror may
ship metadata/code only after the explicit first-public-source approval gate is
cleared; trained weights and embeddings remain release artifacts only after the
ML-1 benchmark and model-card gates are green.

Current mirror evidence is recorded in the latest ML mirror publication audit.
Use the audit rather than copying commit heads into this handoff, because every
documentation or artifact refresh can advance the monorepo or local ML mirror
head without changing the publication decision.

- `tamandua-server`: published and clean in the mirror audit.
- `tamandua-detection-validation`: published and clean in the mirror audit.
- `tamandua-ml`: hold remains active; remote is still empty; staging is clean
  locally in the mirror audit and must not be pushed as a public mirror.

## Evidence Anchors

Use these artifacts as the current authority for ML state:

- Platform readiness: `docs/benchmarks/runs/20260621T-ml-platform-readiness-post-win-template-gate-threading.json`
- Guarded Wave 1 command packet: `docs/benchmarks/runs/20260621T-ml-wave1-guarded-run-command-packet-post-readiness-refresh.json`
- Mirror publication audit: `docs/benchmarks/runs/20260621T-ml-mirror-publication-post-lab-root-sync.json`
- Post-organization mirror publication audit:
  `docs/benchmarks/runs/20260622T-ml-mirror-publication-audit-post-detection-validation-organization.json`
- Post-organization goal snapshot:
  `docs/benchmarks/runs/20260622T-ml-goal-snapshot-post-detection-validation-organization.json`
- Post-organization execution status:
  `docs/benchmarks/runs/20260622T-ml-execution-status-post-detection-validation-organization.json`
- Agent ONNX parity smoke: `docs/benchmarks/runs/20260621T-ml3-agent-parity-with-win-template-local-inference.json`
- Agent rush benchmark execution packet:
  `docs/benchmarks/runs/20260621T-ml-agent-rush-benchmark-execution-packet.json`
- Agent rush ML-1 contract:
  `docs/benchmarks/runs/20260621T-ml1-model-benchmark-contract-agent-rush.json`
- Agent rush ML-4 contract:
  `docs/benchmarks/runs/20260621T-ml4-api-benchmark-contract-agent-rush.json`
- Agent rush ML-5 contract:
  `docs/benchmarks/runs/20260621T-ml5-pipeline-benchmark-contract-agent-rush.json`
- Agent rush ML-6 contract:
  `docs/benchmarks/runs/20260621T-ml6-holdout-benchmark-contract-agent-rush.json`
- Agent rush ML-3 production gap audit:
  `docs/benchmarks/runs/20260621T-ml3-agent-production-gap-audit-agent-rush.json`
- Agent rush benchmark lane rollup:
  `docs/benchmarks/runs/20260621T-ml-benchmark-lane-rollup-agent-rush.json`
- Agent rush benchmark actionability audit:
  `docs/benchmarks/runs/20260621T-ml-benchmark-actionability-audit-agent-rush.json`
- ML-2/ML-3 operator go/no-go with local inference context:
  `docs/benchmarks/runs/20260621T-ml-wave2-ml2-ml3-agent-smoke-local-inference-go-no-go.json`
- Benchmark unblock queue after WIN-TEMPLATE gate threading:
  `docs/benchmarks/runs/20260621T-ml-benchmark-unblock-queue-post-win-template-gate-threading.json`
- Benchmark unblock validation status after WIN-TEMPLATE gate threading:
  `docs/benchmarks/runs/20260621T-ml-benchmark-unblock-validation-status-post-win-template-gate-threading.json`
- Benchmark unblock consistency after WIN-TEMPLATE gate threading:
  `docs/benchmarks/runs/20260621T-ml-benchmark-unblock-validation-status-consistency-post-win-template-gate-threading.json`
- Current post-403 source decision:
  `docs/benchmarks/runs/20260621T-ml-wave1-source-decision-post-malwarebazaar-403.json`
- Current next-action run:
  `docs/benchmarks/runs/20260621T-ml-next-action-post-malwarebazaar-403-virusshare-lab-root.run.json`
- Current next gate authorization:
  `docs/benchmarks/runs/20260621T-ml-next-gate-authorization-post-malwarebazaar-403-virusshare-lab-root.json`
- Current next operator packet:
  `docs/benchmarks/runs/20260621T-ml-next-operator-post-malwarebazaar-403-virusshare-lab-root-packet.json`
- VX metadata inventory: `docs/benchmarks/runs/ml-vx-inthewild-inventory.json`
- Governed acquisition dry run: `docs/benchmarks/runs/ml-prod-candidate-v1-acquisition-dry-run.json`
- Agent alert/API/GUI E2E audit:
  `docs/benchmarks/runs/20260622T-agent-alert-gui-e2e.json`
- Agent ML alert bridge fix:
  `docs/benchmarks/runs/20260622T-agent-ml-alert-bridge-fix.json`

## 2026-06-22 Agent Alert Update

Authenticated server/API/frontend evidence now proves that the WIN-TEMPLATE
agent has existing alerts visible through `/api/v1/alerts` and `/app/alerts`.
That evidence does not prove ML detection: the sampled WIN-TEMPLATE alert source
is `behavioral`, the demo trigger returned 403, and no deployed agent-side ONNX
alert creation was observed.

The code bridge for future ML alerts was tightened after the audit:
agent ML scan results now emit a top-level `DetectionType::Ml`, and server
evidence extraction now derives `source: "ml"` / `detection_source: "ml"` for
alert API and GUI filtering. The Rust agent check passed with
`cargo check --features onnx,ml-local`; Elixir tests were updated but not run in
this shell because `mix`/`elixir` are unavailable on PATH.

Next required proof remains a live WIN-TEMPLATE run that creates a new alert
from an ONNX/local ML malicious fixture and shows it in the GUI plus
`alerts:feed`.

Do not use older `*-validation-only.run.json` receipts as current Wave 1
authorization. They are historical validation evidence only.

## Benchmark Order

The benchmark program should stay dependency-gated in this order:

1. Wave 1 governed acquisition and sanitized manifest publication.
2. ML-1 standalone model quality benchmark and model card.
3. ML-2 PyTorch versus ONNX parity.
4. ML-3 agent-local ONNX inference/parity.
5. ML-4 server API/service benchmark.
6. ML-5 full Tamandua replay using server plus agent surfaces.
7. ML-6 cross-time holdout robustness.

The current 1K bootstrap checkpoint is functional smoke evidence only. It is
not production detection evidence, and its reported 100% accuracy must remain
documented as expected overfit on a small training volume.

The latest agent-side ONNX/WIN-TEMPLATE local inference smoke is green for the
synthetic fixture contract and proves the Rust agent parity path can consume the
frozen fixture. It scored 4 safe fixtures as 3 benign and 1 malicious, with
`win_template_seeded_high_entropy_control` recorded as the current false-positive
candidate. It is not `ml-prod-candidate-v1` evidence and must not unblock ML-5
or public detection claims.

The direct agent ONNX rerun on 2026-06-22 used
`apps/tamandua_agent/src/bin/ml_agent_onnx_parity.rs` against
`docs/benchmarks/runs/20260604T174850Z-ml-agent-parity-fixture.json` and wrote
`docs/benchmarks/runs/20260622T-agent-onnx-parity-direct-agent-bench.json`.
Result: `passed=true`, `sample_count=6`, `verdict_agreement=1.0`,
`verdict_matches=6`, and `max_abs_probability_delta=0.000027954578` against the
allowed `0.0001` tolerance. The paired report is
`docs/benchmarks/runs/20260622T-ml3-agent-onnx-parity-direct-agent-bench-with-win-template.json`.
This is direct proof that the Rust agent ONNX path runs and matches the frozen
synthetic fixture. It is still not malware detection evidence because the
fixture is synthetic and not the canonical `ml-prod-candidate-v1` benchmark.

The matching WIN-TEMPLATE local checkpoint rerun is
`docs/benchmarks/runs/20260622T-win-template-ml-probe-local-inference-direct-agent-bench.json`.
It completed local inference on 4 deterministic non-malware fixtures: 3 benign,
1 malicious (`win_template_seeded_high_entropy_control`). That malicious verdict
remains a false-positive candidate, not a detection success.

The 2026-06-22 production mTLS recovery succeeded after aligning the server
agent CA bundle with the DB-backed Tamandua EDR CA and restoring
`MTLS_REQUIRED=true`. The WIN-TEMPLATE agent
`5622e06b-81ae-4f33-85e1-0f7fcae090ef` connected, registered, joined its agent
channel, and emitted telemetry. A single-test agent-bound smoke then passed:
`docs/benchmarks/runs/20260622T-agent-bound-win-template-live-response-smoke.json`
and `.md` show `Gate: pass`, `covered=1`, `missed=0`, with evidence sources
including endpoint process/file/network/DNS, kernel driver, and
`live_response_audit=1`. This proves agent-bound execution and telemetry
collection through Tamandua, not ML detection.

The agent-side ONNX rerun with ONNX Runtime 1.23.2 is
`docs/benchmarks/runs/20260622T-agent-onnx-parity-agent-online-rerun.json`.
Result: `passed=true`, `sample_count=6`, `verdict_agreement=1.0`,
`verdict_matches=6`, and `max_abs_probability_delta=0.000027954578`. This
proves the Rust agent ONNX path still matches the frozen synthetic fixture while
the WIN-TEMPLATE agent is online; it is not malware detection evidence.

The current safe WIN-TEMPLATE ML checkpoint probe is
`docs/benchmarks/runs/20260622T-win-template-ml-probe-local-inference-agent-online.json`.
It ran local inference on 4 deterministic non-malware fixtures: 3 benign and 1
malicious verdict on `win_template_seeded_high_entropy_control`. That remains a
false-positive candidate and a `no_go_for_detection_claims` signal until the
canonical `ml-prod-candidate-v1` dataset and benchmark gates exist.

The follow-up agent-bound WIN-TEMPLATE run was attempted with
`tools/detection_validation/tamandua_detection_validation.py --execute` and
generated `docs/benchmarks/runs/exec-windows-ml-probe-win-template-direct-agent-bench.json`.
It did not reach endpoint execution: `infrastructure_blocked=true`,
`quality_gate=fail`, 12/12 deterministic Windows roadmap checks reported
`infra_blocked`, and the live readiness blocker was
`tamandua_ctl_target_agent_missing` / `tamandua_ctl_agent_missing`. The database
record for the requested WIN-TEMPLATE agent was offline with stale
`last_seen_at=2026-05-27T03:53:00`. This is an infrastructure/lab freshness
blocker, not an ML model result.

The WIN-TEMPLATE lab recovery path was then exercised through Proxmox/QGA on
2026-06-22. QGA readiness passed for VM `1521`, the agent service was installed
and observed running with PID `2548`, and the driver service `tamandua` was also
running. The install generated the current backend agent record
`fa7d2282-e896-4937-aedf-57b0c7454080`. The recovered agent-bound validation
still did not execute detection tests: `quality_gate=fail`, 12/12 Windows
roadmap checks remained `infra_blocked`, and readiness reported
`agent_status_registered`/`agent_status_offline` with `last_seen_at=2026-06-22T14:07:38`.
QGA file diagnostics confirmed `D:\ProgramData\Tamandua\config\agent.toml`
exists, but the standard `D:\ProgramData\Tamandua\logs\agent.log` path was not
present. The remaining blocker is backend heartbeat/live-response readiness, not
model execution.

New WIN-TEMPLATE recovery artifacts:

- `docs/benchmarks/runs/20260622T-win-template-qga-readiness-current-agent-id/20260622T141950Z-windows-proxmox-qga-readiness-probe.md`
- `docs/benchmarks/runs/20260622T-win-template-qga-agent-service-after-start-current-agent-id/20260622T142345Z-windows-qga-agent-service-probe.json`
- `docs/benchmarks/runs/20260622T-win-template-qga-start-foreground-current-agent-id/20260622T142008Z-windows-qga-start-foreground-agent.json`
- `docs/benchmarks/runs/exec-windows-ml-probe-win-template-recovered-agent.json`
- `docs/benchmarks/runs/20260622T-win-template-agent-log-tail-after-recovery.json`

The agent rush benchmark packet now records dry-run contracts for ML-1, ML-4,
ML-5, and ML-6 plus the existing ML-2 inference contract and ML-3 smoke report.
Those contracts are execution scaffolding only: every generated report keeps
`quality_gate.status=not_run` except the ML-3 smoke report, which is explicitly
bounded to the frozen synthetic fixture. The packet makes the next production
step concrete without changing the publication decision: Wave 1 governed
acquisition must produce `ml-prod-candidate-v1-dataset-manifest.json` before the
canonical ML-1 benchmark can run.

The packet is now covered by
`schemas/ml_agent_rush_benchmark_execution_packet_v1.schema.json` and
`tools/detection_validation/validate_ml_contracts.py`:

```powershell
python tools\detection_validation\validate_ml_contracts.py --ml-agent-rush-benchmark-execution-packet docs\benchmarks\runs\20260621T-ml-agent-rush-benchmark-execution-packet.json
```

The validator enforces that the packet keeps `production_detection_claim=no_go`,
keeps `tamandua_ml_public_mirror_push=no_go`, preserves Wave 1 as the next
unblock, and tracks the WIN-TEMPLATE malicious prediction on a non-malware
fixture as a false-positive candidate.

The latest agent-rush gap/readiness refresh records:

- ML-3 production gap audit: `status=blocked`, `blocker_count=4`,
  `unblocks_ml5_platform_replay=false`.
- Benchmark lane rollup: 7 lanes, 1 ready smoke lane, 6 blocked lanes,
  43 pending unblock items, and `next_operator_publication_decision=hold_do_not_push`.
- Benchmark actionability audit: `actionable=true` for validation-only
  commands, with `evidence_usable_for_goal=0` and next unblock still
  `wave1_governed_acquisition`.

The benchmark unblock queue has been refreshed after this smoke result. It still
has 43 pending items, zero resolved items, zero unknown evidence targets, and
`next_operator_publication_decision=hold_do_not_push`. The current post-403
operator packet is not ready for guarded Wave 1 acquisition:
`ready_for_guarded_execution=false`,
`authorized_for_guarded_execution=false`, source auth is bound to
`VIRUSSHARE_API_KEY`, and the current action is
`blocked:set_required_env:VIRUSSHARE_API_KEY`. This keeps the ML mirror hold in
place. The older post-WIN-TEMPLATE MalwareBazaar-governed packet remains
historical route evidence only.

The post-organization execution status keeps Wave 1 blocked on
`TAMANDUA_ML_DATA_ROOT` and `VIRUSSHARE_API_KEY`. It also records that
`TAMANDUA_ML_DATA_ROOT` must point outside the Git checkout before any guarded
acquisition run is allowed. The post-organization mirror audit keeps
`tamandua-ml` at `hold_do_not_push`; detection-validation remains publishable
as validation evidence only.

## Parallelization

Safe to parallelize now:

- Contract/schema validation and detection-validation mirror refresh.
- Documentation and operator handoff refresh.
- Frontend/server publication audits and deploy readiness checks.
- ML dry-run planners that do not acquire samples, train, export, infer, or call
  live services.

Blocked until Wave 1 produces the canonical sanitized manifest:

- ML-1 candidate training.
- ONNX candidate publication.
- Agent-local ONNX benchmark against a production candidate.
- Service benchmark against a production candidate.
- Full Tamandua replay and cross-time holdout.

Unblocked validation-only work after the 2026-06-22 direct agent run:

- Keep the direct agent ONNX parity artifact in both mirrors as smoke evidence.
- Add the `ml-prod-candidate-v1` agent fixture and ONNX export after Wave 1
  acquisition and ML-1 training complete.
- Promote the WIN-TEMPLATE command from local fixture inference to agent-bound
  execution only after backend credentials and live lab transport are available.

## VX Underground Policy

VX Underground/InTheWild is currently metadata-only. The current command packet
does not authorize archive downloads, and `TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD`
must remain unset for Wave 1 governed acquisition.

Use VX/InTheWild as a holdout and temporal coverage source after the metadata
inventory is converted into a governed acquisition path in an isolated lab. Do
not mix VX samples into train/validation/test splits until a new source-decision
artifact explicitly authorizes that change and updates the holdout policy.

## Operator Sequence

Before any real acquisition, complete env remediation and rerun the no-execution
VirusShare fallback readiness path:

```powershell
$env:TAMANDUA_ML_DATA_ROOT = 'D:\treant\tamandua_ml_lab_data'
$env:VIRUSSHARE_API_KEY = '<from isolated lab secret store>'
.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_virusshare_fallback_readiness_launcher.ps1
```

Only after readiness and refreshed authorization select `launch_package`, run in
the isolated lab with the external data root configured and guards set:

```powershell
$env:TAMANDUA_ML_DATA_ROOT = 'D:\treant\tamandua_ml_lab_data'
$env:VIRUSSHARE_API_KEY = '<from isolated lab secret store>'
$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1'
.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_virusshare_fallback_acquisition_launcher.ps1 -Execute
Remove-Item Env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION -ErrorAction SilentlyContinue
Remove-Item Env:VIRUSSHARE_API_KEY -ErrorAction SilentlyContinue
```

After acquisition, refresh receipts before any manifest publish:

```powershell
.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_post_acquisition_refresh_launcher.ps1
```

Only after the acquisition receipt is intake-ready:

```powershell
$env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH = '1'
.\docs\benchmarks\runs\20260604T-ml-execution-plan.handoff\wave_1_manifest_publish_launcher.ps1 -Execute
Remove-Item Env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH -ErrorAction SilentlyContinue
```

Raw samples and external sample trees must never be copied into Git.

## Front Runtime Note

The new BaseUI/server frontend code is published in source and mirror form, but
the live runtime assets are not updated yet. The current front deploy readiness
audit shows the publish command is blocked by the missing
`TAMANDUA_LAB_VM_PASSWORD` secret:

```powershell
.\deploy\scripts\proxmox\deploy-tamandua-front-assets-light.ps1 -NoBuild
```

That runtime deployment is independent from the ML mirror hold.
