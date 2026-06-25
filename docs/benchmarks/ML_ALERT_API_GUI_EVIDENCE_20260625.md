# ML Alert API GUI Evidence - 2026-06-25

Status: controlled server/API/GUI evidence. This is not a live agent telemetry
emission proof.

Follow-up implementation now exists for the missing live proof:
`apps/tamandua_agent/src/bin/ml_detection_telemetry_smoke.rs` scans a file with
local ONNX, emits `DetectionType::Ml`, and sends the event through the real
agent telemetry transport.

## What Ran

- A controlled `events` row and linked `alerts` row were created on the lab
  backend for LAB-DC01.
- The alert used `source=ml`, `detection_source=ml`, `detection_type=ml`,
  `rule_name=ML_MALWARE_TROJAN`, `prediction=trojan`, and
  `model_version=malware_smell_knn`.
- Authenticated HTTP probes queried:
  - `GET /api/v1/alerts/:id`
  - `GET /api/v1/alerts?source=ml&per_page=5`
  - `GET /api/v1/events`
  - `GET /api/v1/timeline`
  - `GET /app/alerts`
  - `GET /app/alerts/:id`
  - `GET /app/events`

## Evidence IDs

- Run ID: `20260625T-ml-alert-api-gui-evidence`
- Alert ID: `d9eadbc6-dcc2-41d2-8e4a-1d020665f19f`
- Event ID: `de19458c-3d73-44ab-b2bc-88b394e240ef`
- Agent ID: `c5706989-46e8-4ecb-9feb-75c5f3a42f1a` (`LAB-DC01`)

## Results

| Surface | Result |
| --- | --- |
| `/api/v1/alerts/:id` | `200`, alert source serialized as `ml` |
| `/api/v1/alerts?source=ml` | `200`, returned the controlled alert |
| `/api/v1/events` | `200`, returned the linked event |
| `/api/v1/timeline` | `200`, returned the linked file event |
| `/app/alerts` | `200`, page contains alert ID, `ml`, and run ID |
| `/app/alerts/:id` | `200`, page contains alert ID, `ml`, and run ID |
| `/app/events` | `200`, page contains `ml` and run ID |

## Claim Boundary

Proven:

- The server/API can store and serialize an ML alert as `source=ml`.
- The `source=ml` API filter returns the ML alert.
- The GUI alert and event routes load without 500s and include the ML evidence.
- Timeline API loads the linked event without 500s.

Not proven:

- The currently running Windows agent emitted this alert through telemetry.
- The live `alerts:feed` socket broadcast carried this specific alert.
- The current bootstrap ML model has acceptable production false-positive rate.

Next required proof:

1. Run `ml_detection_telemetry_smoke` on a Windows host with model/runtime
   dependencies installed and valid agent socket credentials.
2. Send the resulting telemetry event through the live agent socket.
3. Assert a new `source=ml` alert appears in `/api/v1/alerts`, `/api/v1/timeline`,
   `/app/alerts`, and `alerts:feed`.
