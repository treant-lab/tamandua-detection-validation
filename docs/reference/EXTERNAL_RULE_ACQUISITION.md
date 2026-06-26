# External Rule Acquisition

This workflow turns external detection ecosystems into Tamandua-authored
coverage, execution-prep profiles, and improvement roadmaps.

It does not vendor upstream rule bodies into this repository. External clones
stay outside the monorepo under `D:\treant\external`, and generated Tamandua
artifacts keep source IDs, commits, licenses, behavior intent, telemetry
contracts, and validation plans.

Do not copy rule bodies, upstream queries, conditions, XML, investigation
guides, or prose into Tamandua-authored content. External projects are used as
practical references for behavior, telemetry needs, and validation coverage;
every promoted rule, scenario, threshold, description, and fixture must be
written as Tamandua-owned semantic rewrite work.

## External Sources

| Source | Local path | Use |
| --- | --- | --- |
| Elastic detection-rules | `D:\treant\external\elastic-detection-rules` | Detection metadata and ATT&CK coverage |
| SigmaHQ rules | `D:\treant\external\sigmahq-sigma` | Community rule coverage and platform references |
| Wazuh ruleset | `D:\treant\external\wazuh-ruleset` | Host rule coverage, auth and OS signal references |
| LOLBAS | `D:\treant\external\lolbas` | Windows living-off-the-land execution references |
| GTFOBins | `D:\treant\external\gtfobins` | Linux/macOS living-off-the-land execution references |
| Splunk Security Content | `D:\treant\external\splunk-security-content` | Analytic metadata, data sources, identity/cloud/network coverage |
| Azure Sentinel | `D:\treant\external\azure-sentinel` | KQL analytic metadata, identity/cloud/network coverage |

## Generated Artifacts

| Artifact | Purpose |
| --- | --- |
| `roadmaps/external_rule_inventory.json` | One row per upstream rule/item, including skipped items and reasons |
| `roadmaps/external_rule_coverage_map.json` | Platform and ATT&CK coverage map across sources |
| `roadmaps/external_rule_semantic_rewrite_candidates.json` | Tamandua-authored rewrite queue by platform and technique |
| `roadmaps/external_rule_global_improvement_roadmap.json` | Agent, collector, schema, D&R, runner, and documentation improvement map |
| `roadmaps/external_rule_implementation_backlog.json` | Code-area implementation backlog grouped by owner area |
| `roadmaps/external_rule_event_contracts.json` | Normalized event contracts required by the rewrite queue |
| `profiles/*_external_rule_coverage_map.json` | Report-only source coverage probes |
| `profiles/*_external_semantic_rewrite_*.json` | Safe execution-prep profiles for semantic rewrite candidates |
| `docs/benchmarks/EXTERNAL_RULE_COVERAGE_MAPPING.md` | Human-readable coverage summary |
| `docs/benchmarks/EXTERNAL_RULE_EXECUTION_PLAN.md` | Execution order and promotion gate |
| `docs/benchmarks/EXTERNAL_RULE_IMPLEMENTATION_BACKLOG.md` | Human-readable code-area implementation backlog |
| `docs/benchmarks/EXTERNAL_RULE_EVENT_CONTRACTS.md` | Human-readable collector and event contract matrix |

## Regeneration

```powershell
python scripts\generate_external_rule_coverage_map.py `
  --elastic-root 'D:\treant\external\elastic-detection-rules' `
  --sigmahq-root 'D:\treant\external\sigmahq-sigma' `
  --wazuh-root 'D:\treant\external\wazuh-ruleset' `
  --lolbas-root 'D:\treant\external\lolbas' `
  --gtfobins-root 'D:\treant\external\gtfobins' `
  --splunk-root 'D:\treant\external\splunk-security-content' `
  --sentinel-root 'D:\treant\external\azure-sentinel'
```

For release-quality regeneration, pass the source commit flags printed by
`git -C <external clone> rev-parse --short=12 HEAD`.

## Validation

```powershell
python scripts\validate_profile_catalog.py --strict
python scripts\external_rule_event_contracts.py
python scripts\validate_external_rule_readiness.py
python scripts\external_rule_implementation_backlog.py
python -m py_compile scripts\generate_external_rule_coverage_map.py scripts\tamandua_detection_validation.py scripts\external_rule_event_contracts.py scripts\validate_external_rule_readiness.py
python scripts\tamandua_detection_validation.py --profile profiles\windows_external_semantic_rewrite_p0_p1_execution.json --benchmark-lane external-semantic-rewrite-execution
```

## Promotion Rules

1. Use external implementations as practical inspiration.
2. Promote only Tamandua-authored rule logic, fields, thresholds, descriptions, and tests.
3. Keep source provenance: repo, commit, source IDs, source mix, and license class.
4. Pair every promoted D&R candidate with benign and suspicious fixtures.
5. Treat `technique-specific` probes as execution-ready first, then `technique-family`, then `platform-generic`.
6. Use the global improvement roadmap to schedule agent, collector, schema, D&R, and runner work before claiming detection coverage.
