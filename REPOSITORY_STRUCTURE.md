# Tamandua Detection Validation Repository Structure

This repository is a standalone validation toolkit. The root intentionally keeps
only repository metadata, docs, fixtures, profiles, schemas, scripts, and tests.
Executable probes and validators live under `scripts/`.

ML validation boundary: current ML artifacts are validation-ready only,
not production-trained, and production validation remains pending through the
ML-1..ML-6 gates.

## Top-Level Layout

| Path | Purpose |
| --- | --- |
| `scripts/` | Standalone probes, scorecard generators, validators, shared helpers, and operational utilities. |
| `tests/` | Pytest coverage, including focused contract tests and the legacy all-in-one harness. See `tests/README.md` for prefix families. |
| `fixtures/` | Synthetic fixtures and replay inputs. No raw malware or secrets. |
| `profiles/` | JSON execution profiles for repeatable validation runs. |
| `roadmaps/` | Roadmap source shards consumed by roadmap tooling. |
| `schemas/` | JSON Schemas copied from the monorepo for standalone contract validation. |
| `docs/benchmarks/` | Curated evidence, handoff notes, and selected run artifacts explicitly allowlisted by the mirror manifest. |
| `.github/` | Mirror-local CI and repository metadata. |

The repository root should not contain Python entry points. Operators call
scripts with `python scripts/<name>.py ...`; tests live under `tests/`. Use
[PROBE_CATALOG.md](./PROBE_CATALOG.md) as the maintained index for probe
domains, ML contract validators, platform probes, and publication rules.
The current flat pytest layout is intentional for standalone compatibility;
organize new tests by the filename families documented in `tests/README.md`
until a dedicated package migration is planned and tested.

## Artifact Policy

- Do not commit generated `runs/`, `generated/`, cache, or bytecode output.
- Do not commit raw samples, malware, trained model weights, API keys, or lab
  secrets.
- Curated `docs/benchmarks/runs/*.json` and `*.md` files may be committed only
  when the monorepo mirror manifest names the artifact explicitly.
- ML model weights, reference embeddings, and markers remain release artifacts
  only after the ML gates clear. They are not source-mirror content.

## Standalone Root Resolution

Most ML validators use `scripts/root_resolver.py`.

Inside the monorepo, paths resolve to the monorepo root automatically. Inside the
standalone mirror, set `TAMANDUA_ROOT` when a validator needs monorepo example
contracts or benchmark artifacts that are not copied into the mirror:

```bash
TAMANDUA_ROOT=/path/to/tamandua python scripts/validate_ml_contracts.py --help
```

## Current ML Evidence Boundaries

The current mirror may contain ML planning and smoke evidence, but it does not
claim production detection quality.

- WIN-TEMPLATE local checkpoint inference completed on non-malware fixtures and
  recorded a false-positive candidate.
- Agent-side ONNX evidence is smoke parity against a frozen synthetic fixture.
- WIN-TEMPLATE agent-bound execution is now proven for a deterministic
  live-response smoke through `tamandua-ctl`; this proves agent connectivity and
  execution evidence, not ML malware detection.
- App Guard/RASP protected WebView replay fixtures are static contracts only:
  they prove metadata-only event shape and alert/timeline projection
  expectations, not live ingestion, physical Android/iOS collection, or store
  release readiness.
- Agent-rush ML-1, ML-4, ML-5, and ML-6 reports are dry-run contracts with
  `quality_gate.status=not_run`.
- ML-3 production gap remains blocked until `ml-prod-candidate-v1` model,
  ONNX, and parity artifacts exist.
- `tamandua-ml` public mirror remains on HOLD until the experimental release
  gate clears.

## Useful Commands

Validate the agent-rush benchmark packet:

```bash
TAMANDUA_ROOT=/path/to/tamandua \
python scripts/validate_ml_contracts.py \
  --ml-agent-rush-benchmark-execution-packet \
  docs/benchmarks/runs/20260621T-ml-agent-rush-benchmark-execution-packet.json
```

Validate the latest ML-3 production gap audit:

```bash
TAMANDUA_ROOT=/path/to/tamandua \
python scripts/validate_ml_contracts.py \
  --ml3-agent-production-gap-audit \
  docs/benchmarks/runs/20260621T-ml3-agent-production-gap-audit-agent-rush.json
```

Run focused contract tests:

```bash
python -m pytest \
  tests/test_validate_ml_agent_rush_benchmark_execution_packet.py \
  tests/test_validate_ml3_agent_production_gap_audit.py \
  -q
```

Run a probe help check:

```bash
python scripts/linux_ebpf_readiness_probe.py --help
```
