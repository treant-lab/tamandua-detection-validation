# Test Suite Organization

This directory intentionally keeps pytest modules importable from a flat
`tests/test_*.py` layout for standalone mirror compatibility. Use filename
prefixes as the primary grouping rule until a larger package migration is
needed.

## Families

| Prefix | Purpose |
| --- | --- |
| `test_validate_ml_wave*` | ML wave readiness, operator handoff, acceptance, execution, and go/no-go gates. |
| `test_validate_ml_benchmark*` | ML benchmark report, execution matrix, unblock queue, handoff, and critical path contracts. |
| `test_validate_ml_*` | ML acquisition, dataset manifest, model, replay, quality, platform, and publication validators outside the wave/benchmark lanes. |
| `test_validate_ml3_*` | ML-3 production-gap audit contracts that predate the generic `test_validate_ml_*` naming. |
| `test_validate_server_*` | Server/frontend publication and deploy readiness validators. |
| `test_validate_app_guard_*` | App Guard/RASP replay fixture validators. |
| `test_ml_*` | ML public claim and training-roadmap guardrails. |
| `test_tamandua_detection_validation.py` | Legacy runner smoke for the standalone toolkit entry point. |
| `test_archive_stale_runs.py` | Generated/run artifact hygiene. |

## Subprocess Policy (audited 2026-07-08)

Gate-script invocations were converted to in-process execution via
`inprocess_gate_cli.run_cli_in_process` (importlib + patched `sys.argv`,
returns a `subprocess.CompletedProcess`-shaped result). The remaining
`subprocess.run` call-sites in this suite are deliberate and must stay
subprocess:

- **7 `sys.executable` smoke call-sites** — exactly one per converted gate
  script (`test_benchmark_claim_maturity_gate.py`,
  `test_driver_kernel_containment_claim_guard.py`,
  `test_governed_fp_fn_corpus_gate.py`, `test_mobile_app_guard_benchmark_gate.py`,
  `test_physical_attack_lab_evidence.py`,
  `test_posture_inventory_compliance_readiness_gate.py`,
  `test_validate_app_guard_rasp_replay_fixtures.py`). They cover the real
  process boundary: interpreter startup, `if __name__ == "__main__"` guard,
  argv handoff, and true process exit codes. Do not convert them.
- **104 PowerShell call-sites** in `test_tamandua_detection_validation.py`
  (`["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", <*.ps1>, ...]`).
  The targets are `.ps1` operator tools (readiness checks, env-bundle
  init/validate/runner, launcher/prelaunch guards) — there is no Python
  entrypoint to import, so the importlib in-process pattern is inapplicable.
  These tests validate the PowerShell CLI contract itself: real
  `powershell.exe` exit codes and JSON emitted to console stdout. Porting the
  `.ps1` logic to Python would change what is under test.

Net effect: zero convertible call-sites remain; the suite's residual wall
time is dominated by `powershell.exe` process spawns, which are the contract
under test.

## Parallel Execution (pytest-xdist)

`pytest-xdist` 3.8.0 is already installed in the `C:/Python310` environment
(no installation required). Measured on 2026-07-08 (full suite,
`--no-cov -p no:cacheprovider`):

| Mode | Result | Wall time |
| --- | --- | --- |
| serial | 1511 passed, 5 skipped | 252.5s |
| `-n auto` | 1511 passed, 5 skipped | 96.0s |

Recommendation: use `-n auto` for local iteration (~2.6x). Evidence is a
single green parallel run; tests use `tmp_path` isolation and the suite
showed no ordering/shared-state failures, but keep the serial invocation as
the canonical gate until parallel runs accumulate more history.

## Placement Rules

- Add new tests under `tests/`; do not add pytest files at repository root.
- Prefer the existing prefix family before creating a new naming lane.
- Keep fixtures under `fixtures/`, schemas under `schemas/`, and generated run
  artifacts out of the repository unless the mirror manifest explicitly
  allowlists them.
- If a family grows large enough to require subdirectories, move it as a
  dedicated migration with pytest discovery verified in the standalone mirror.
