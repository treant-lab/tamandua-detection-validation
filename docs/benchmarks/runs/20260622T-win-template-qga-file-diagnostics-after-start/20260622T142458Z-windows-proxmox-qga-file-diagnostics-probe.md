# Windows Proxmox QGA File Diagnostics Probe

- Run ID: `20260622T142458Z-windows-proxmox-qga-file-diagnostics-probe`
- Gate: `pass`
- Ready for read-only file diagnostics: `true`

## Results

| Test | Status | Gap |
|------|--------|-----|
| `proxmox-api-authenticated` | `covered` | `none` |
| `qga-file-commands-advertised` | `covered` | `none` |
| `proxmox-agent-readonly-diagnostics-transport` | `covered` | `none` |

## Next Action

- Target: `192.168.12.149` node `Default` VM `1521`
- Missing diagnostics: ``
- Required env: `-`
- Observed 501 on file-open: `false`
- Action: QGA file diagnostics are green; keep this proof paired with current QGA guest-exec readiness.

## Claim Boundary

This artifact proves only whether Proxmox exposes QGA guest-file endpoints for read-only lab diagnostics. It does not read Tamandua secrets into the artifact. When guest-file endpoints are unavailable, it may run a bounded benign guest-exec metadata fallback that checks candidate path existence without reading file contents. It does not prove detection coverage.
