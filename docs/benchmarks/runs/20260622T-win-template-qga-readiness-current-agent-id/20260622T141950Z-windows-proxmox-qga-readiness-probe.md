# Windows Proxmox QGA Readiness Probe

- Run ID: `20260622T141950Z-windows-proxmox-qga-readiness-probe`
- Gate: `pass`
- Ready for bounded execution: `true`

## Results

| Test | Status | Gap |
|------|--------|-----|
| `proxmox-api-authenticated` | `covered` | `none` |
| `proxmox-api-vm-monitor-permission` | `covered` | `none` |
| `proxmox-vm-running` | `covered` | `none` |
| `proxmox-qga-ping` | `covered` | `none` |
| `proxmox-qga-readonly-hostname` | `covered` | `none` |
| `proxmox-qga-guest-exec-supported` | `covered` | `none` |
| `proxmox-qga-bounded-guest-exec` | `covered` | `none` |

## Next Action

- Target: `192.168.12.149` node `Default` VM `1521`
- Missing readiness: ``
- Required env: `-`
- Action: QGA readiness is green; keep the file diagnostics probe current before using QGA as a broad Windows execution transport.

## Claim Boundary

This artifact proves only Proxmox/QGA readiness for bounded lab execution. It does not run attack workloads, does not restart the VM, does not mutate the Tamandua server, and does not prove detection coverage.
