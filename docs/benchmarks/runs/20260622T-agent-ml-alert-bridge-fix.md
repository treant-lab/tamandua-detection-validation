# Agent ML Alert Bridge Fix - 2026-06-22

Status: code bridge fixed, live WIN-TEMPLATE proof still pending.

Claim boundary: this artifact proves a focused code change and local Rust
compilation only. It does not prove that the currently deployed WIN-TEMPLATE
agent emitted a new ML alert in production.

## Changes

- `apps/tamandua_agent/src/main.rs`: malicious ML scan results now emit a
  top-level `DetectionType::Ml` detection and set telemetry metadata source to
  `ml_analysis`.
- `apps/tamandua_server/lib/tamandua_server/detection/evidence.ex`: extracted
  alert detection metadata now includes `source` and `detection_source` derived
  from the normalized detection type.
- `apps/tamandua_server/test/tamandua_server/detection/evidence_test.exs`: adds
  coverage that `Ml` maps to `source: "ml"` and `detection_source: "ml"`.

## Verification

- Passed: `cargo check --features onnx,ml-local` in `apps/tamandua_agent`.
- Blocked: Elixir test execution. `mix` and `elixir` are not available in this
  shell PATH.

## Live Evidence Boundary

The authenticated server/API/frontend audit in
`docs/benchmarks/runs/20260622T-agent-alert-gui-e2e.md` showed:

- Alerts API for WIN-TEMPLATE returned 200 with 18 existing alerts.
- GUI `/app/alerts` returned 200.
- Existing WIN-TEMPLATE alert source was `behavioral`, not `ml`.
- Demo trigger returned 403 and did not create a synthetic alert.

Next proof required: deploy the updated agent/server bridge, run a controlled
malicious fixture through WIN-TEMPLATE with ONNX/local ML enabled, and assert a
new alert whose detection metadata has `source: "ml"` and whose GUI row appears
through `/app/alerts` plus `alerts:feed`.
