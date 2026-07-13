# Tamandua Detection Validation

A standalone Python toolkit of detection-validation probes, fixtures, and
scorecards for the [Tamandua EDR](https://github.com/treant-lab) platform. Each
script is an independent probe that exercises a slice of detection or platform
behavior and emits a structured result used to build readiness scorecards.

## Overview

- **`scripts/`** — standalone probes and validators (e.g. eBPF readiness, control-plane
  tenant safety, ATT&CK coverage matrix, crash-resilience fixtures).
- **`tests/`** — focused pytest contract tests for ML gates, schemas,
  publication audits, and curated evidence.
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

Governed FP/FN corpus boundary: `scripts/governed_fp_fn_corpus_gate.py` validates
the goodware/malware corpus hold artifact. It requires lineage, sample counts,
locked threshold/orientation, FPR/FNR arithmetic, retained-critical scenario
coverage, and explicit blocked external claims. A pass means the hold is honest;
it does not promote local bootstrap numbers to production false-positive rate,
malware false-negative rate, vendor parity, or live protection claims.

Latest WIN-TEMPLATE status: the production mTLS path was restored and
`5622e06b-81ae-4f33-85e1-0f7fcae090ef` reached `online` through the server.
`20260622T-agent-bound-win-template-live-response-smoke` passed as an
agent-bound deterministic execution smoke. ML evidence remains bounded to safe
fixtures: the Rust agent ONNX parity rerun passed on the frozen synthetic
fixture, while the local checkpoint WIN-TEMPLATE probe still records one
false-positive candidate on a non-malware high-entropy control.

Mobile/App Guard validation boundary: `fixtures/app_guard_rasp_replay_v1.json`
adds metadata-only protected WebView/RASP replay fixtures,
`fixtures/browser_guard_rasp_replay_v1.json` adds direct Browser Guard/Web SDK
replay fixtures, and
`fixtures/mobile_app_guard_aggressive_replay_v1.json` adds aggressive benchmark
coverage for Magisk/Zygisk, Frida attach/spawn, debugger, hook frameworks,
WebView/browser tamper, APK repack/integrity, cert pinning bypass, DoH/exfil,
spyware-like behavior, and goodware FP gates. They validate event shape plus
expected alert/timeline projection, including active signals, privacy markers,
server fanout topics, "must not 500" contract expectations, and honest
implemented/roadmap labels. They do not claim live backend persistence,
live signed ingestion, live anti-replay enforcement, browser-extension
packaging, native Android/iOS collector behavior, iOS native/XCFramework
release readiness, physical-device collection, governed attack-lab protection,
SDK shielding efficacy, store readiness, or production malware accuracy. Treat
fixture and local smoke passes as non-claims unless separate live, iOS, and
lab/device evidence packets are present.

See [REPOSITORY_STRUCTURE.md](./REPOSITORY_STRUCTURE.md) for the standalone
mirror layout and artifact policy, and [PROBE_CATALOG.md](./PROBE_CATALOG.md)
for the logical grouping of root-level probes, validators, and test families.

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
python scripts/linux_ebpf_readiness_probe.py --help
python scripts/attack_coverage_matrix.py --help
```

Probes write JSON/Markdown results to their configured output directory.
Generated `runs/` and `generated/` outputs are not version-controlled.
Curated evidence under `docs/benchmarks/runs/` is version-controlled only when
the monorepo mirror manifest names the file explicitly.

Validate replay fixtures, including App Guard/RASP:

```bash
python scripts/validate_replay_fixtures.py
python scripts/mobile_app_guard_benchmark_gate.py
python scripts/mobile_sdk_temp_hygiene.py --staged
python scripts/mobile_sdk_temp_hygiene.py --tracked
```

`mobile_app_guard_benchmark_gate.py` fails when the fixture boundary drops
required live, iOS, physical-device, or governed-lab evidence requirements.
`mobile_sdk_temp_hygiene.py --staged` blocks newly staged temp, env/secret
backup, and sensitive log artifacts; `--tracked` allows the explicit legacy
tracked exceptions while continuing to report non-exempt paths.

Validate the static Plugins/BOF/dynamic module boundary:

```bash
python scripts/plugins_bof_static_readiness_probe.py
```

This gate is source/docs only. A pass means plugin runtime, BOF loader, and
dynamic collector work remains explicitly design-dormant or lab-scoped; it does
not prove runtime execution, WASM sandbox safety, BOF prevention/removal, or
production policy enablement.

## Validate ML Contracts

The ML contract validator can run inside the standalone mirror. If default
example contracts are not present in the mirror, point `TAMANDUA_ROOT` at a
monorepo checkout:

```bash
TAMANDUA_ROOT=/path/to/tamandua \
python scripts/validate_ml_contracts.py \
  --ml-agent-rush-benchmark-execution-packet \
  docs/benchmarks/runs/20260621T-ml-agent-rush-benchmark-execution-packet.json
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). New probes should be self-contained,
deterministic where possible, and must not fabricate results.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
