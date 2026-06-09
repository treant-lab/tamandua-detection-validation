# Tamandua Detection Validation

A standalone Python toolkit of detection-validation probes, fixtures, and
scorecards for the [Tamandua EDR](https://github.com/treant-lab) platform. Each
script is an independent probe that exercises a slice of detection or platform
behavior and emits a structured result used to build readiness scorecards.

## Overview

- **Probes** (`*.py`) — ~140 standalone scripts (e.g. eBPF readiness, control-plane
  tenant safety, ATT&CK coverage matrix, crash-resilience fixtures).
- **`fixtures/`** — synthetic payloads and event fixtures consumed by the probes.
- **Scorecards / roadmaps** — curated Markdown artifacts the probes feed into.

Probes are designed to be honest: they report what was actually observed, and
benchmark caveats (e.g. label-leakage holdouts, untrained sequence heads) are
preserved verbatim rather than smoothed over.

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

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). New probes should be self-contained,
deterministic where possible, and must not fabricate results.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
