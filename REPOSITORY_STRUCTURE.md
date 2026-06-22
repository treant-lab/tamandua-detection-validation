# Tamandua Detection Validation Repository Structure

This repository is a standalone validation toolkit. The root intentionally keeps
probe scripts flat so each probe can be executed directly with `python
<probe>.py --help` after the mirror is synced.

## Top-Level Layout

| Path | Purpose |
| --- | --- |
| `*.py` | Standalone probes, scorecard generators, validators, and tests. |
| `fixtures/` | Synthetic fixtures and replay inputs. No raw malware or secrets. |
| `profiles/` | JSON execution profiles for repeatable validation runs. |
| `roadmaps/` | Roadmap source shards consumed by roadmap tooling. |
| `schemas/` | JSON Schemas copied from the monorepo for standalone contract validation. |
| `docs/benchmarks/` | Curated evidence, handoff notes, and selected run artifacts explicitly allowlisted by the mirror manifest. |
| `.github/` | Mirror-local CI and repository metadata. |

## Artifact Policy

- Do not commit generated `runs/`, `generated/`, cache, or bytecode output.
- Do not commit raw samples, malware, trained model weights, API keys, or lab
  secrets.
- Curated `docs/benchmarks/runs/*.json` and `*.md` files may be committed only
  when the monorepo mirror manifest names the artifact explicitly.
- ML model weights, reference embeddings, and markers remain release artifacts
  only after the ML gates clear. They are not source-mirror content.

## Standalone Root Resolution

Most ML validators use `root_resolver.py`.

Inside the monorepo, paths resolve to the monorepo root automatically. Inside the
standalone mirror, set `TAMANDUA_ROOT` when a validator needs monorepo example
contracts or benchmark artifacts that are not copied into the mirror:

```bash
TAMANDUA_ROOT=/path/to/tamandua python validate_ml_contracts.py --help
```

## Current ML Evidence Boundaries

The current mirror may contain ML planning and smoke evidence, but it does not
claim production detection quality.

- WIN-TEMPLATE local checkpoint inference completed on non-malware fixtures and
  recorded a false-positive candidate.
- Agent-side ONNX evidence is smoke parity against a frozen synthetic fixture.
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
python validate_ml_contracts.py \
  --ml-agent-rush-benchmark-execution-packet \
  docs/benchmarks/runs/20260621T-ml-agent-rush-benchmark-execution-packet.json
```

Validate the latest ML-3 production gap audit:

```bash
TAMANDUA_ROOT=/path/to/tamandua \
python validate_ml_contracts.py \
  --ml3-agent-production-gap-audit \
  docs/benchmarks/runs/20260621T-ml3-agent-production-gap-audit-agent-rush.json
```

Run focused contract tests:

```bash
python -m pytest \
  test_validate_ml_agent_rush_benchmark_execution_packet.py \
  test_validate_ml3_agent_production_gap_audit.py \
  -q
```

Run a probe help check:

```bash
python linux_ebpf_readiness_probe.py --help
```
