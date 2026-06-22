# Tamandua Detection Validation Run exec-windows-ml-probe-win-template-direct-agent-bench

- Profile: `windows-roadmap-p0-existing-sensor-contract`
- Started: `2026-06-22T14:11:10.611037Z`
- Finished: `2026-06-22T14:11:35.090639Z`
- Mode: `execute`
- Benchmark lane: `enterprise-eval`
- Target VMID: `0`
- Agent ID: `5a2c7e97-cd1c-449f-b85b-8fb1711798b9`
- Hostname: `unknown`
- OS build: `unknown`
- Agent hash: `unknown`
- Driver hash: `unknown`
- Git commit: `40afad13`

## Summary

- Maturity score: `50/100`
- Maturity band: `calibration`
- Recommended claim: `Tamandua deterministic regression; not external-tool-backed`
- External comparison claim allowed: `False`
- Tests: `12`
- Covered: `0`
- Partial: `0`
- Missed: `0`
- Dry-run planned only: `0`
- Upstream-backed tests: `0`
- Fallback-command tests: `0`
- Deterministic-command tests: `12`
- Executor mix: `command=12`
- Execution classes: `deterministic=12`
- Claim levels: `deterministic=12`
- Gap categories: `infrastructure=12`
- Unknown source events: `0`
- Unexpected high/critical events: `0`
- Unexpected high/critical alerts: `0`
- Excluded benchmark setup alerts: `0`
- Excluded stale source-timestamp events: `0`
- Missing driver raw events: `0`
- Driver channel drops: `0`
- Driver kernel drops: `0`
- Missing expected fields: `0`
- Missing expected values: `0`
- Missing expected correlations: `0`
- Investigable alert gaps: `0`
- Gate: `fail`

## Scorecard

```json
{
  "analytic_quality": 1.0,
  "blocking_gaps": [
    "quality_gate_failed",
    "deterministic_commands_present",
    "not_all_tests_upstream_backed"
  ],
  "context_quality": 1.0,
  "covered_rate": 0.0,
  "driver_quality": 1.0,
  "external_claim_allowed": false,
  "field_quality": 1.0,
  "maturity_band": "calibration",
  "maturity_score": 50,
  "noise_quality": 1.0,
  "recommended_claim": "Tamandua deterministic regression; not external-tool-backed",
  "telemetry_rate": 0.0,
  "upstream_rate": 0.0
}
```

## Results

| Test | Executor | Status | Coverage | Missing telemetry | Missing fields | Missing driver raw | Missing detections | Missing alerts | Missing correlations | Alert context gaps | Driver drops | Unknown source events | Unexpected high/critical events | Unexpected high/critical alerts | Excluded setup alerts |
|------|----------|--------|----------|-------------------|----------------|--------------------|--------------------|----------------|----------------------|--------------------|--------------|-----------------------|---------------------------------|---------------------------------|-----------------------|
| `roadmap-win-initialaccess-001-t1566-001` Spearphishing Attachment: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-execution-001-t1059-001` PowerShell: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-execution-009-t1059-001` PowerShell: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-persistence-001-t1547-001` Registry Run Keys / Startup Folder: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-privilegeescalation-001-t1548-002` Bypass User Account Control: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-defenseevasion-001-t1027` Obfuscated Files or Information: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-defenseevasion-009-t1036` Masquerading: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-credentialaccess-001-t1003-001` LSASS Memory: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-credentialaccess-009-t1552-001` Credentials In Files: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-discovery-001-t1082` System Information Discovery: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-lateralmovement-001-t1021-002` SMB/Windows Admin Shares: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |
| `roadmap-win-lateralmovement-009-t1047` Windows Management Instrumentation: telemetry contract | `Deterministic command` | `infra_blocked` | `T:-; D:-; A:-; L:-; R:-; F:-` | `-` | `-` | `-` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` |

## Actionable Gaps

| Test | Gap category | Status | Validation category | Techniques | Missing signals |
|------|--------------|--------|---------------------|------------|-----------------|
| `roadmap-win-initialaccess-001-t1566-001` | `infrastructure` | `infra_blocked` | `telemetry` | `T1566.001` | `-` |
| `roadmap-win-execution-001-t1059-001` | `infrastructure` | `infra_blocked` | `telemetry` | `T1059.001` | `-` |
| `roadmap-win-execution-009-t1059-001` | `infrastructure` | `infra_blocked` | `telemetry` | `T1059.001` | `-` |
| `roadmap-win-persistence-001-t1547-001` | `infrastructure` | `infra_blocked` | `telemetry` | `T1547.001` | `-` |
| `roadmap-win-privilegeescalation-001-t1548-002` | `infrastructure` | `infra_blocked` | `telemetry` | `T1548.002` | `-` |
| `roadmap-win-defenseevasion-001-t1027` | `infrastructure` | `infra_blocked` | `telemetry` | `T1027` | `-` |
| `roadmap-win-defenseevasion-009-t1036` | `infrastructure` | `infra_blocked` | `telemetry` | `T1036` | `-` |
| `roadmap-win-credentialaccess-001-t1003-001` | `infrastructure` | `infra_blocked` | `telemetry` | `T1003.001` | `-` |
| `roadmap-win-credentialaccess-009-t1552-001` | `infrastructure` | `infra_blocked` | `telemetry` | `T1552.001` | `-` |
| `roadmap-win-discovery-001-t1082` | `infrastructure` | `infra_blocked` | `telemetry` | `T1082` | `-` |
| `roadmap-win-lateralmovement-001-t1021-002` | `infrastructure` | `infra_blocked` | `telemetry` | `T1021.002` | `-` |
| `roadmap-win-lateralmovement-009-t1047` | `infrastructure` | `infra_blocked` | `telemetry` | `T1047` | `-` |

## ATT&CK Tactic Coverage

| Tactic | Tests | Covered | Partial | Missed | Failed | Upstream-backed |
|--------|-------|---------|---------|--------|--------|-----------------|
| `credential-access` | `2` | `0` | `0` | `0` | `0` | `0` |
| `defense-evasion` | `2` | `0` | `0` | `0` | `0` | `0` |
| `discovery` | `1` | `0` | `0` | `0` | `0` | `0` |
| `execution` | `2` | `0` | `0` | `0` | `0` | `0` |
| `initial-access` | `1` | `0` | `0` | `0` | `0` | `0` |
| `lateral-movement` | `2` | `0` | `0` | `0` | `0` | `0` |
| `persistence` | `1` | `0` | `0` | `0` | `0` | `0` |
| `privilege-escalation` | `1` | `0` | `0` | `0` | `0` | `0` |

## Validation Category Coverage

| Category | Tests | Covered | Partial | Missed | Failed | Upstream-backed | Gap categories |
|----------|-------|---------|---------|--------|--------|-----------------|----------------|
| `telemetry` | `12` | `0` | `0` | `0` | `0` | `0` | `infrastructure=12` |

## ATT&CK Technique Coverage

| Technique | Tests | Covered | Partial | Missed | Failed | Upstream-backed | Evidence sources |
|-----------|-------|---------|---------|--------|--------|-----------------|------------------|
| `T1003.001` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1021.002` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1027` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1036` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1047` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1059.001` | `2` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1082` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1547.001` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1548.002` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1552.001` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |
| `T1566.001` | `1` | `0` | `0` | `0` | `0` | `0` | `-` |

## Upstream Readiness

```json
{
  "atomic_red_team": {
    "items": {
      "all_atomic_capable_tests_upstream_backed": false,
      "atomic_profile_selected": false,
      "atomic_upstream_lane": false,
      "no_fallback_commands": true,
      "quality_gate_passed": false
    },
    "lane": "enterprise-eval",
    "ready": false
  },
  "caldera": {
    "items": {
      "adversary_group_and_paw_recorded": false,
      "caldera_profile_selected": false,
      "caldera_upstream_lane": false,
      "operation_proof_recorded": false,
      "operations_succeeded": false,
      "quality_gate_passed": false
    },
    "lane": "enterprise-eval",
    "ready": false
  }
}
```

## Preflight

- Outer exit code: `-`
- Guest stdout captured: `no`
- Guest stderr captured: `no`

Full command lines, stdout/stderr and raw probe payloads are intentionally kept in the JSON artifact, not in this Markdown report.

## Quality Gate

```json
{
  "actionable_gaps": [
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "initial-access"
      ],
      "techniques": [
        "T1566.001"
      ],
      "test_id": "roadmap-win-initialaccess-001-t1566-001",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "execution"
      ],
      "techniques": [
        "T1059.001"
      ],
      "test_id": "roadmap-win-execution-001-t1059-001",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "execution"
      ],
      "techniques": [
        "T1059.001"
      ],
      "test_id": "roadmap-win-execution-009-t1059-001",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "persistence"
      ],
      "techniques": [
        "T1547.001"
      ],
      "test_id": "roadmap-win-persistence-001-t1547-001",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "privilege-escalation"
      ],
      "techniques": [
        "T1548.002"
      ],
      "test_id": "roadmap-win-privilegeescalation-001-t1548-002",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "defense-evasion"
      ],
      "techniques": [
        "T1027"
      ],
      "test_id": "roadmap-win-defenseevasion-001-t1027",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "defense-evasion"
      ],
      "techniques": [
        "T1036"
      ],
      "test_id": "roadmap-win-defenseevasion-009-t1036",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "credential-access"
      ],
      "techniques": [
        "T1003.001"
      ],
      "test_id": "roadmap-win-credentialaccess-001-t1003-001",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "credential-access"
      ],
      "techniques": [
        "T1552.001"
      ],
      "test_id": "roadmap-win-credentialaccess-009-t1552-001",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "discovery"
      ],
      "techniques": [
        "T1082"
      ],
      "test_id": "roadmap-win-discovery-001-t1082",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "lateral-movement"
      ],
      "techniques": [
        "T1021.002"
      ],
      "test_id": "roadmap-win-lateralmovement-001-t1021-002",
      "validation_category": "telemetry"
    },
    {
      "execution_class": "deterministic",
      "fallback_used": false,
      "gap_category": "infrastructure",
      "missing_expected_alerts": [],
      "missing_expected_correlations": [],
      "missing_expected_detections": [],
      "missing_expected_driver_raw_event_types": [],
      "missing_expected_fields": [],
      "missing_expected_telemetry": [],
      "missing_expected_values": [],
      "status": "infra_blocked",
      "tactics": [
        "lateral-movement"
      ],
      "techniques": [
        "T1047"
      ],
      "test_id": "roadmap-win-lateralmovement-009-t1047",
      "validation_category": "telemetry"
    }
  ],
  "failures": [
    "infrastructure_blocked_tests"
  ],
  "gap_category_counts": {
    "infrastructure": 12
  },
  "passed": false,
  "thresholds": {
    "benchmark_lane": "enterprise-eval",
    "fail_on_missed": true,
    "fail_on_partial": true,
    "fresh_restore_provenance_required_when_claimed": true,
    "max_driver_channel_drops": 0,
    "max_driver_kernel_drops": 0,
    "max_unexpected_high_critical": 0,
    "max_unknown_source": 0,
    "require_upstream": false
  }
}
```

## Notes

- Raw JSON artifact contains commands, stdout/stderr, event summaries, alert summaries, and server log excerpts.
- Markdown is intentionally concise so it can be reviewed as an executive benchmark artifact.
