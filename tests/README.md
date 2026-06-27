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

## Placement Rules

- Add new tests under `tests/`; do not add pytest files at repository root.
- Prefer the existing prefix family before creating a new naming lane.
- Keep fixtures under `fixtures/`, schemas under `schemas/`, and generated run
  artifacts out of the repository unless the mirror manifest explicitly
  allowlists them.
- If a family grows large enough to require subdirectories, move it as a
  dedicated migration with pytest discovery verified in the standalone mirror.
