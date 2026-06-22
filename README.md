# Tamandua Detection Validation

A standalone Python toolkit of detection-validation probes, fixtures, and
scorecards for the [Tamandua EDR](https://github.com/treant-lab) platform. Each
script is an independent probe that exercises a slice of detection or platform
behavior and emits a structured result used to build readiness scorecards.

## Overview

- **Probes** (`*.py`) — standalone scripts (e.g. eBPF readiness, control-plane
  tenant safety, ATT&CK coverage matrix, crash-resilience fixtures).
- **`fixtures/`** — synthetic payloads and event fixtures consumed by the probes.
- **`profiles/`** — JSON profiles for repeatable probe execution.
- **`roadmaps/`** — source roadmap shards consumed by roadmap/index generators.
- **`schemas/`** — JSON Schemas copied into standalone mirrors for contract
  validation.
- **`docs/benchmarks/`** — selected, versioned evidence and handoff notes copied
  from the monorepo. Raw generated output remains excluded unless explicitly
  allowlisted by the mirror manifest.
- **Scorecards / roadmaps** — curated Markdown artifacts the probes feed into.

Probes are designed to be honest: they report what was actually observed, and
benchmark caveats (e.g. label-leakage holdouts, untrained sequence heads) are
preserved verbatim rather than smoothed over.

ML validation boundary: current ML artifacts are validation-ready only,
not production-trained, and production validation remains pending through the
ML-1..ML-6 gates.

See [REPOSITORY_STRUCTURE.md](./REPOSITORY_STRUCTURE.md) for the standalone
mirror layout and artifact policy, and [PROBE_CATALOG.md](./PROBE_CATALOG.md)
for the logical grouping of root-level probes, validators, and tests.

## Prerequisites

- Python 3.11+.
- Third-party dependencies: `requests` and `PyYAML`. Everything else is standard
  library.

```bash
python -m venv .venv && . .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install requests pyyaml
```

## Run a probe

Each probe is invoked directly and supports `--help`:

```bash
python linux_ebpf_readiness_probe.py --help
python attack_coverage_matrix.py --help
```

Probes write JSON/Markdown results to their configured output directory.
Generated `runs/` and `generated/` outputs are not version-controlled.
Curated evidence under `docs/benchmarks/runs/` is version-controlled only when
the monorepo mirror manifest names the file explicitly.

## Validate ML Contracts

The ML contract validator can run inside the standalone mirror. If default
example contracts are not present in the mirror, point `TAMANDUA_ROOT` at a
monorepo checkout:

```bash
TAMANDUA_ROOT=/path/to/tamandua \
python validate_ml_contracts.py \
  --ml-agent-rush-benchmark-execution-packet \
  docs/benchmarks/runs/20260621T-ml-agent-rush-benchmark-execution-packet.json
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). New probes should be self-contained,
deterministic where possible, and must not fabricate results.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
