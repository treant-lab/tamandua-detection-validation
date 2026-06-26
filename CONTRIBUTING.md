# Contributing to tamandua-detection-validation

This component is part of the Tamandua EDR platform. For the canonical
contribution guide — code of conduct, contribution tracks, and community
norms — see the community repository:

  https://github.com/treant-lab/tamandua-community

Please also read this component's [README](./README.md) and
[PROBE_CATALOG.md](./PROBE_CATALOG.md) for the root-file organization rules.

## Component build & test

```bash
python -m venv .venv && . .venv/bin/activate
pip install requests pyyaml
python scripts/linux_ebpf_readiness_probe.py --help
```

## Before opening a PR

- New probes must be self-contained and deterministic where possible.
- Do not commit generated runs/ or generated/ output.
- Keep changes scoped; avoid unrelated refactors.
- Do not commit secrets or large binaries.
- Do not fabricate or overstate results; preserve benchmark caveats verbatim.
