# AI Model Scanner Scorecard

- Source artifact: `docs/benchmarks/AI_MODEL_SCANNER_VALIDATION_20260801T154402Z.json`
- Run source: `ce4b46b4fc6e9b5a134669fb1666cd8d0dcda5c6` on `main`, **working tree dirty**
- Corpus: `11` malicious samples, `3` clean samples
- Scanner availability: PickleGuard, GGUFGuard, SafetensorsGuard, ONNXGuard, WeightAnalyzer, SpectralAnalyzer
- Status: small-corpus smoke/regression evidence only
- Superseded artifact: `AI_MODEL_SCANNER_VALIDATION_20260630T134213Z.json` (30 Jun) — retained for history, **no longer current behavior**

## Current Metrics

| Scanner | TP | TN | FP | FN | Errors | TPR | FPR | Precision | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PickleGuard | 1 | 1 | 0 | 0 | 0 | 100% | 0% | 100% | 100% |
| ONNXGuard | 1 | 1 | 0 | 0 | 0 | 100% | 0% | 100% | 100% |
| GGUFGuard | 2 | 0 | 0 | 0 | 0 | 100% | 0% | 100% | 100% |
| SafetensorsGuard | 7 | 1 | 0 | 0 | 0 | 100% | 0% | 100% | 100% |
| WeightAnalyzer | 2 | 2 | 0 | 3 | 5 | 40% | 0% | 100% | 57.14% |
| SpectralAnalyzer | 0 | 2 | 0 | 5 | 5 | 0% | 0% | 0% | 28.57% |

## Reconciliation Note (2026-08-01)

The 30 Jun artifact this scorecard previously cited predated the 14 Jul GGUF
expansion in `3868662cd`. Rerunning the harness against current source moved
two rows, not one:

- **GGUFGuard 50% → 100%** (1 TP/1 FN → 2 TP/0 FN). Both malicious GGUF samples
  are retained; `prompt_injection.gguf` is now detected at risk score 0.550 and
  `gguf_jinja2_injection.gguf` at 0.998. The focused regression test
  `test_gguf_guard_detects_prompt_injection_sample_metadata` passes
  (`tests/test_gguf_guard.py`, 21 passed), so the focused test, the harness and
  this table now agree.
- **SafetensorsGuard 28.57% → 100%** (2 TP/5 FN → 7 TP/0 FN). This drift was
  *not* anticipated when the rerun was scoped; it was found by reconciling the
  whole table rather than only the row known to be stale.

`WeightAnalyzer` and `SpectralAnalyzer` are unchanged and still carry 5 errors
each — those are weight-extraction failures on `.pkl` and malformed
`.safetensors` fixtures, not detections.

**Corroborating unit-test evidence (2026-08-03).** The guard layer's own test
suite was run against current source and is green: **71 passed, 1 skipped**
across `test_gguf_guard.py`, `test_keras_guard.py`, `test_lightgbm_guard.py`,
`test_onnx_guard.py`, `test_pickle_guard.py` and `test_model_package_guard.py`.
This is independent of the harness numbers above and of the API test surface,
which currently cannot be collected on this host — 23 test modules fail at
import with `cannot import name 'Sentinel' from 'typing_extensions'`, a broken
local install (pip metadata reports 4.15.0 but the installed file defines no
`Sentinel`) rather than a repository defect. The guard tests are unaffected
because they do not import the pydantic/FastAPI layer.

Read this as scanner-level regression evidence only. It does not widen the
claim boundary below: these are unit tests over synthetic fixtures, not a
production corpus, and they say nothing about detection rates on real-world
malicious models.

**Authority caveat.** The run above was taken with `source_dirty: true`, so it
is a current-source *diagnostic*, not a reproducible benchmark. It is
sufficient to retire the stale 30 Jun numbers, which were demonstrably wrong
for current behavior, but a citable canonical artifact requires a rerun from a
clean tree. The harness now records `provenance` (source SHA, dirty flag,
branch, harness SHA-256 and last commit, Python version, and SHA-256 for every
corpus sample) so that this distinction is visible in the artifact itself
rather than inferred — the absence of exactly this binding is how the stale
result went unnoticed for a month.

## Claim Boundary

This scorecard is a small-corpus validation snapshot and is
not production-ready performance evidence. It can support scanner
smoke/regression tracking only.

WeightAnalyzer and SpectralAnalyzer coverage remains limited by weight
extraction behavior on adversarial or unsupported samples. PyTorch pickle
weight extraction is intentionally constrained by safe-loading behavior, and
several semantic model attacks remain out of scope for format-only guards.
Production claims require broader corpora, repeatability evidence, calibrated
thresholds, and adversarial/evasion testing.
