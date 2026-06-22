# Agent Alert GUI E2E - 2026-06-22

Status: partial pass
Claim boundary: authenticated server/API/frontend evidence only. This does not prove ML malware detection or agent-side ONNX alert creation.

## Target

- Base URL: `http://192.168.12.146:4000`
- Agent ID: `5622e06b-81ae-4f33-85e1-0f7fcae090ef`

## Results

- Login page status: 200
- Login POST status: 
- Alerts API before trigger: status 200, count 18
- First alert before trigger: `774b9f18-ea8d-4899-a7d6-8cdff0262ae0`, source `behavioral`, severity `high`, status `new`, agent `5622e06b-81ae-4f33-85e1-0f7fcae090ef`
- GUI `/app/alerts`: status 200, body length 275755
- Demo trigger: status 403, created=False
- Alerts API after trigger: status 200, count 18
- First alert after trigger: `774b9f18-ea8d-4899-a7d6-8cdff0262ae0`, source `behavioral`, severity `high`, status `new`, agent `5622e06b-81ae-4f33-85e1-0f7fcae090ef`

## Verdict

- Alerts API authenticated: True
- GUI alerts route authenticated: True
- Demo alert created: False
- Agent ML detection proven: false
- GUI live socket broadcast proven: false

## Next Required Work

- Wire or verify agent-side ONNX/ML verdict emission into the server alert ingestion path.
- Run a controlled benign/malicious fixture through the WIN-TEMPLATE agent and assert a new alert references the agent, fixture hash, and ML source.
- Use browser automation to verify the created alert appears in the GUI alerts table and via the alerts:feed socket.
