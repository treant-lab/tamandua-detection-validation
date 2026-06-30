# AI Model Scanner Scorecard

- Source artifact: `docs/benchmarks/AI_MODEL_SCANNER_VALIDATION_20260630T134213Z.json`
- Corpus: `11` malicious samples, `3` clean samples
- Scanner availability: PickleGuard, GGUFGuard, SafetensorsGuard, ONNXGuard, WeightAnalyzer, SpectralAnalyzer
- Status: small-corpus smoke/regression evidence only

## Current Metrics

| Scanner | TP | TN | FP | FN | Errors | TPR | FPR | Precision | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PickleGuard | 1 | 1 | 0 | 0 | 0 | 100% | 0% | 100% | 100% |
| ONNXGuard | 1 | 1 | 0 | 0 | 0 | 100% | 0% | 100% | 100% |
| GGUFGuard | 1 | 0 | 0 | 1 | 0 | 50% | 0% | 100% | 50% |
| SafetensorsGuard | 2 | 1 | 0 | 5 | 0 | 28.57% | 0% | 100% | 37.5% |
| WeightAnalyzer | 2 | 2 | 0 | 3 | 5 | 40% | 0% | 100% | 57.14% |
| SpectralAnalyzer | 0 | 2 | 0 | 5 | 5 | 0% | 0% | 0% | 28.57% |

## Claim Boundary

This scorecard is a small-corpus validation snapshot and is not
production-ready performance evidence. It can support scanner smoke/regression
tracking only.

WeightAnalyzer and SpectralAnalyzer coverage remains limited by weight
extraction behavior on adversarial or unsupported samples. PyTorch pickle
weight extraction is intentionally constrained by safe-loading behavior, and
several semantic model attacks remain out of scope for format-only guards.
Production claims require broader corpora, repeatability evidence, calibrated
thresholds, and adversarial/evasion testing.
