# ML Agent ONNX Direct Detection - 2026-06-25

Status: smoke evidence only. This is not a production model-quality claim.

## What Ran

- Built `apps/tamandua_agent/src/bin/ml_onnx_scan.rs` with Cargo feature
  `onnx`.
- Added and compiled `apps/tamandua_agent/src/bin/ml_detection_telemetry_smoke.rs`
  with Cargo feature `onnx`. This binary scans one file locally with ONNX,
  builds a `TelemetryEvent` with `DetectionType::Ml`, and sends it through the
  real `BackendClient` telemetry path.
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

Agent-bound telemetry smoke command shape:

```powershell
cargo run --features onnx --bin ml_detection_telemetry_smoke -- `
  --config C:\ProgramData\Tamandua\config\agent.toml `
  --model C:\ProgramData\Tamandua\models\malware_smell_knn.onnx `
  --sample C:\ProgramData\Tamandua\ml-bench\samples\malware_00000.bin `
  --output C:\ProgramData\Tamandua\ml-bench\ml-telemetry-smoke.json
```

Use `--server-url`, `--agent-id`, and `--auth-token` only for lab override
runs. `TAMANDUA_AGENT_AUTH_TOKEN` is also accepted for the token override.

## Claim Boundary

Proven:

- The agent-side ONNX scanner can run on a Windows lab host.
- The KNN ONNX export can emit a malicious verdict on a staged malware fixture.
- The agent now has a compiled smoke binary that converts local ONNX detection
  into real agent telemetry.

Not proven:

- Production model quality.
- Acceptable false-positive rate.
- A live LAB/WIN-TEMPLATE run of `ml_detection_telemetry_smoke` with valid
  socket credentials/certificates.
- WIN-TEMPLATE transport stability.

Next work:

1. Retrain/calibrate using governed malware/goodware sources before publishing
   `tamandua-ml`.
2. Run `ml_detection_telemetry_smoke` on LAB-DC01 or WIN-TEMPLATE with the
   production agent config and verify the new alert.
3. Verify the alert in `/api/v1/alerts`, timeline/events, GUI, and
   `alerts:feed`.

Follow-up evidence:

- `docs/benchmarks/ML_ALERT_API_GUI_EVIDENCE_20260625.md` proves the
  server/API/GUI path can store and render a controlled `source=ml` alert. It
  does not prove the currently running agent emitted that alert through
  telemetry.
- `apps/tamandua_server/test/tamandua_server/telemetry/ml_agent_detection_alert_test.exs`
  covers the server-side contract: ML detection telemetry creates an ML alert
  and broadcasts `alerts:feed`.
