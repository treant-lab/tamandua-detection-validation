# ML Agent ONNX Direct Detection - 2026-06-25

Status: smoke evidence only. This is not a production model-quality claim.

## What Ran

- Built `apps/tamandua_agent/src/bin/ml_onnx_scan.rs` with Cargo feature
  `onnx`.
- Exported `apps/tamandua_ml/models/malware_smell_knn.onnx` with
  `apps/tamandua_ml/scripts/export_onnx_knn.py`.
- Ran direct local smoke benchmarks against 25 malware and 25 goodware files.
- Ran `ml_onnx_scan.exe` on LAB-DC01 (`192.168.12.110`) against
  `malware_00000.bin`.

## Results

| Run | Model | Malware Detection | Goodware FP | Outcome |
| --- | --- | ---: | ---: | --- |
| Local smoke | `malware_smell.onnx` marker wrapper | 0/25 | 0/25 | Non-candidate export |
| Local smoke | `malware_smell_knn.onnx` KNN export | 25/25 | 22/25 | Detects, but FP is unacceptable |
| LAB-DC01 Windows smoke | `malware_smell_knn.onnx` KNN export | 1/1 | Not measured | Detected `trojan`, confidence 1.0 |

LAB-DC01 report:

```json
{
  "is_malicious": true,
  "confidence": 1.0,
  "family": "trojan",
  "family_index": 1,
  "probabilities": [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
  "inference_time_ms": 5410
}
```

## Runtime Notes

The Windows smoke required these DLLs in the scanner directory:

- `onnxruntime.dll`
- `onnxruntime_providers_shared.dll`
- `vcruntime140.dll`
- `vcruntime140_1.dll`
- `msvcp140.dll`
- `msvcp140_1.dll`
- `msvcp140_2.dll`
- `concrt140.dll`

## Claim Boundary

Proven:

- The agent-side ONNX scanner can run on a Windows lab host.
- The KNN ONNX export can emit a malicious verdict on a staged malware fixture.

Not proven:

- Production model quality.
- Acceptable false-positive rate.
- ML alert ingestion in the Tamandua server.
- GUI/timeline/events propagation for a new ML alert.
- WIN-TEMPLATE transport stability.

Next work:

1. Retrain/calibrate using governed malware/goodware sources before publishing
   `tamandua-ml`.
2. Add an agent-bound scan path that creates a real `source=ml` alert.
3. Verify the alert in `/api/v1/alerts`, timeline/events, and GUI.

Follow-up evidence:

- `docs/benchmarks/ML_ALERT_API_GUI_EVIDENCE_20260625.md` proves the
  server/API/GUI path can store and render a controlled `source=ml` alert. It
  does not prove the currently running agent emitted that alert through
  telemetry.
