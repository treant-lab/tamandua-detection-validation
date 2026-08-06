# Tamandua Competitive Gaps Roadmap

Status: active planning index; not release or parity authority
Last updated: 2026-07-21
Change log (this revision): added "TBD harness promotion plan (priority
lanes)" and "Gate dependency graph" sections after the acceptance matrix;
pinned the Guardsquare/Verimatrix XTD acquisition date (2026-02-05) in the
source registry. No matrix rows, IDs, statuses, or commands were changed;
`competitive_roadmap_gate.py --strict` structure is preserved.
Parent: `docs/ROADMAP_HUB.md`

## Purpose and authority

This roadmap converts competitor-oriented gaps into bounded, testable work. It
does not assert feature, vendor, production, prevention, or release parity. The
generated files under `docs/benchmarks/generated/` remain the authority for
readiness and public claims; if this document disagrees with them, generated
authority wins.

Current generated authority says `product_ready=false` and
`external_claim_allowed=false`. Every vendor name below is therefore a
comparison lens, not an equivalence or superiority claim. Existing local,
source, synthetic, and lab evidence must retain those labels. See the latest
[readiness summary](../benchmarks/generated/validation_product_readiness_summary.md)
and [roadmap scorecard](../benchmarks/generated/validation_roadmap_scorecard.md).

Evidence classes are ordered conservatively:
`source_review < smoke_local < synthetic_parity < governed_lab < governed_holdout < production_telemetry < independent_validation`.
Vendor documentation is `vendor_declared`: it describes the vendor's stated
surface, but is not Tamandua evidence and cannot prove effectiveness. A command
prefixed with `TBD:` is an acceptance-contract placeholder, not an existing
tool or a completed result.

## Operating vocabulary

- Priorities: `P0` trust/release blocker; `P1` near-term competitive value;
  `P2` integration or expansion.
- Status: `active` has partial implementation but incomplete acceptance evidence;
  `mapped` has a defined contract but implementation has not started;
  `external-blocked` needs a governed device, runner, license, credential,
  customer environment, or independent lab; `hold` cannot be promoted.
- Decisions: `build` is Tamandua-owned; `build evidence` owns only measurement
  and proof; `integrate` uses an external platform; `hybrid` owns contracts and
  evidence while integrating specialized machinery; `defer` has an explicit
  re-entry condition; `kill` is outside product scope.
- An owner is a lane, not implicit authorization. The root team board assigns
  one writer per component before implementation.

## Current implementation snapshot

Fresh structural audit: 2026-07-17. The defined competitive universe is split
into 89 executable core items and 12 adjacent-category backlog items. This is
scope completeness for the currently named comparison set, not a claim that
every security vendor or future market category is permanently known.

The executable matrix currently contains 89 stable items: 15 `active`, 44
`mapped`, 26 `external-blocked`, and 4 `hold`. Thirteen rows name an existing
local command; 76 intentionally retain a `TBD:` command because their harness
does not exist. The three foundation slices with fresh local structural
evidence are `CG-BMK-001-A` (competitive source registry), `CG-SIEM-001-A`
(draft interoperability registry), and `CG-CNA-001-A` (CNAPP wording/surface
freeze). They are not vendor comparison results.

The matrix shape, IDs, dependencies, status totals and synchronized snapshot are
checked by `python tools/detection_validation/scripts/competitive_roadmap_gate.py --strict`.
That gate validates planning structure only.

The source registry has 35 official or normative source records and zero
independent measured records. License review, immutable source snapshots,
exact version/revision pins where still absent, vendor artifacts, governed
physical or endpoint lab runs, and independent review remain open. Therefore
no named Appdome, Guardsquare XTD (formerly Verimatrix), CrowdStrike, SentinelOne, Microsoft,
Palo Alto, Google, Wiz, Prisma, Zimperium, or Lookout parity result is complete.

## Adjacent category watchlist

The detailed matrix deliberately covers mobile shielding, MTD, endpoint/XDR,
SIEM/schema interoperability, CNAPP ingestion/correlation, and competitive
measurement. The following adjacent categories are mapped so they cannot be
mistaken for implemented scope. They enter the executable matrix only after an
official-source record, qualified user/partner, named DRI, bounded acceptance
contract, and build-versus-integrate decision exist.

| Watch ID | Category | Representative comparison candidates | Current boundary | Default decision and re-entry condition |
| --- | --- | --- | --- | --- |
| `CW-ID-001` | Identity threat detection and response | CrowdStrike, Microsoft, SentinelOne | User/process context is not directory identity protection or identity-response parity. | `defer/integrate`; admit after a design partner provides an identity sandbox and attack scenarios. |
| `CW-EXP-001` | Vulnerability, exposure and external attack-surface management | CrowdStrike, Microsoft, Tenable, Qualys, Rapid7 | Asset/software inventory is not vulnerability authority, prioritization, or EASM. | `integrate`; admit one provider after asset identity and remediation ownership are accepted. |
| `CW-DATA-001` | Endpoint DLP and data security | CrowdStrike, Microsoft Purview, Netskope | File/process telemetry is not content classification or exfiltration prevention. | `defer/integrate`; require privacy review, approved data classes and a partner policy corpus. |
| `CW-BRW-001` | Enterprise browser and SSE controls | CrowdStrike, Microsoft, Palo Alto Networks, Netskope | Browser Guard telemetry is not an enterprise browser, CASB, SWG or full SSE plane. | `hybrid`; admit a bounded browser enforcement slice only with managed-browser deployment evidence. |
| `CW-NDR-001` | Network detection and response | Vectra, Darktrace, Corelight, ExtraHop | Endpoint DNS/network events are not packet/sensor-scale NDR. | `integrate`; require a licensed sensor feed and loss/latency/custody contract. |
| `CW-EMAIL-001` | Email and collaboration security | Microsoft, Proofpoint, Mimecast | Email telemetry and response are outside the current owned sensor surface. | `integrate`; require a customer tenant, supported API and case lifecycle. |
| `CW-SOAR-001` | SOAR and case automation | Google SecOps, Microsoft Sentinel, Cortex XSOAR, Splunk SOAR | Internal playbooks do not establish third-party connector breadth or marketplace parity. | `hybrid`; promote only the selected SIEM's case/evidence workflow after connector acceptance. |
| `CW-TI-001` | Threat intelligence platform and feeds | CrowdStrike, Google/Mandiant/VirusTotal, Recorded Future | IOC ingestion is not global intelligence scale, attribution, curation or TIP parity. | `integrate`; require licensed provenance, expiry, confidence and revocation contracts. |
| `CW-MDR-001` | Managed detection and response service | CrowdStrike, SentinelOne, Microsoft, Arctic Wolf | Product automation is not a staffed 24x7 service or SLA. | `defer/partner`; admit only with an operating model, staffing, SLA and liability owner. |
| `CW-AIS-001` | AI application, agent and shadow-AI security | CrowdStrike, Microsoft, Palo Alto Networks, Netskope | Existing AI inventory/gateway work is local product scope, not cross-SaaS or agentic-security parity. | `hybrid`; admit after runtime, browser and SaaS evidence identities are unified. |
| `CW-OT-001` | OT/ICS and unmanaged IoT security | Claroty, Nozomi Networks, Dragos | General endpoint/network collection is not safe OT discovery or response. | `defer/integrate`; require a dedicated passive lab, safety owner and no-active-response policy. |
| `CW-APPSEC-001` | Code, dependency and software-supply-chain security | Snyk, GitHub, Wiz, Prisma Cloud | Artifact provenance gates are not SAST, SCA, secrets or ASPM parity. | `integrate`; admit only a repository-native ingestion/correlation slice with developer ownership. |

### Adjacent-category execution contracts

These contracts close the documentation gap between a short watchlist and an
implementable roadmap. All remain `hold`; every `TBD:` command is planned and
does not exist yet. Admission into the 89-item executable matrix requires the
listed dependencies and an explicit root-owned scope decision.

| Backlog ID | Owner | Dependencies before admission | Acceptance contract | Planned command and evidence |
| --- | --- | --- | --- | --- |
| `CW-ID-001` | Identity Integration | Official sources, design partner, identity sandbox, attack corpus, privacy review, DRI | One pinned provider maps identity, endpoint and response objects with tenant isolation, replay, latency and loss measurements. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category itdr --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/itdr/<run-id>/protocol-receipt.json` |
| `CW-EXP-001` | Exposure Integration | Provider selection, asset identity contract, remediation owner | Imported finding identity, severity, lifecycle, suppression and remediation links survive create/update/delete and tenant-bound replay. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category exposure --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/exposure/<run-id>/protocol-receipt.json` |
| `CW-DATA-001` | Data Security | Privacy/legal review, approved data classes, partner corpus, deletion policy | A pinned corpus measures allow/block/audit behavior, false positives, minimization, policy provenance and evidence deletion. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category data-security --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/data-security/<run-id>/protocol-receipt.json` |
| `CW-BRW-001` | Browser Security | Managed-browser deployment, policy authority, supported connector | One bounded web/file/clipboard control is enforced and audited across upgrade, offline, bypass and clean-workflow cohorts. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category browser-sse --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/browser-sse/<run-id>/protocol-receipt.json` |
| `CW-NDR-001` | Network Integration | Licensed sensor feed, custody contract, capture policy, lab DRI | Loss-aware flow/detection ingestion preserves timestamps, sensor identity, deduplication, retention, latency and endpoint correlation. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category ndr --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/ndr/<run-id>/protocol-receipt.json` |
| `CW-EMAIL-001` | Messaging Integration | Customer tenant, supported API, privacy approval, case owner | Message, user, attachment, URL and response actions remain tenant-bound, idempotent, auditable and case-linked. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category email --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/email/<run-id>/protocol-receipt.json` |
| `CW-SOAR-001` | SecOps Integration | Selected SIEM, accepted case/evidence connector | Bidirectional case/action sync proves authorization, approval, idempotency, timeout, rollback, audit and evidence links. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category soar --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/soar/<run-id>/protocol-receipt.json` |
| `CW-TI-001` | Threat Intel Integration | Licensed feed, provenance and lifecycle policy | Feed lifecycle proves provenance, confidence, expiry, revocation, conflict resolution, tenant visibility and reload receipts. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category threat-intel --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/threat-intel/<run-id>/protocol-receipt.json` |
| `CW-MDR-001` | Service Operations | Operating model, staffing, escalation, liability, regions, service owner | A controlled pilot measures acknowledgement, containment, escalation, evidence quality, handoff and SLA without conflating product and service. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category mdr --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/mdr/<run-id>/pilot-receipt.json` |
| `CW-AIS-001` | AI Security | Unified runtime, browser, SaaS and identity evidence | Pinned scenarios measure AI discovery, policy, prompt/data exposure, tool execution, identity, response and clean-workflow false positives. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category ai-security --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/ai-security/<run-id>/protocol-receipt.json` |
| `CW-OT-001` | OT Safety Integration | Passive lab, safety owner, protocol allowlist, no-active-response policy | Passive-only inventory/correlation proves zero active probes, bounded traffic, protocol provenance, asset identity and response boundaries. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category ot-iot --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/ot-iot/<run-id>/safety-receipt.json` |
| `CW-APPSEC-001` | Developer Security Integration | Repository provider, developer owner, finding identity contract | One repository-native connector proves commit/build/artifact linkage, lifecycle, deduplication, suppression, remediation and tenant boundaries. | `TBD: python tools/competitive/adjacent_protocol_gate.py --category appsec --manifest <path> --strict`; `docs/benchmarks/runs/adjacent/appsec/<run-id>/protocol-receipt.json` |

This watchlist is a portfolio boundary, not an assertion that every future
market category is permanently known. Review it at least quarterly and whenever
a named competitor materially changes platform scope.

## Product decisions and scope

| Surface | Decision | What Tamandua owns | Explicit boundary |
| --- | --- | --- | --- |
| Mobile policy, runtime signals, enforcement, evidence | build | policy model, native signals, server verification, audit, telemetry, response, evidence packet | Runtime detections alone are not shielding or resistance to bypass. |
| Name/control-flow obfuscation | hybrid | baseline R8/ProGuard/Swift stripping configuration, policy, manifest, compatibility and attack measurements | Integrate advanced Android/iOS transformers; do not claim polymorphic protection from baseline minification. |
| String/resource/data encryption | hybrid | secret-removal rules, envelope/key contract, protected asset allowlist and verification | Never embed durable server secrets; integrate compiler/binary tooling for broad code/resource encryption. |
| Code virtualization | integrate | selection policy, protected-region inventory, provenance, overhead and bypass tests | `defer` a Tamandua VM/compiler until three production use cases and a staffed compiler-security lane exist. |
| Binary/IR rewriting | integrate | deterministic post-build gate, signing/provenance, semantic and compatibility tests | `kill` a generic cross-platform binary rewriter; build only narrow transformations with a named threat-model owner. |
| Appdome and Guardsquare XTD (formerly Verimatrix) | hybrid | vendor-neutral policy/evidence plane and protected-build verification | No no-code, anti-tamper, or anti-reversing parity claim without governed hostile and clean-device evidence. |
| Zimperium and Lookout | integrate | Tamandua app/session risk, device identity reconciliation and policy decisions | Their declared mobile intelligence/fleet surface is not comparable to an in-app SDK by feature count. |
| Endpoint/XDR | build | causal graph, sensor contract, durable response, evidence and self-hosted control plane | Do not claim CrowdStrike/SentinelOne/MDE/Cortex parity, fleet scale, or production prevention from source/smoke evidence. |
| Google SecOps, Microsoft Sentinel, Elastic Security | integrate | canonical events, loss-aware exports, connector runtime, health, evidence/case links | `kill` a generic petabyte SIEM and an unbounded catalog of vendor parsers. |
| OCSF and ECS | build | pinned mappings, extension ledger, conformance, compatibility and lifecycle | Schema conformance is interoperability evidence, not SIEM feature parity. |
| Wiz and Prisma Cloud | integrate | finding import, identity/provenance, cloud-to-endpoint graph and investigation UX | Freeze any broad CNAPP wording; do not build generic CSPM, CIEM, DSPM, scanner, or full cloud attack-path engine now. |
| Competitive measurement | build evidence | governed protocols, source registry, immutable manifests, metrics and claim gate | Public vendor superiority/replacement requires independent validation and applicable license permission. |

## Now, next, later

### Now: foundations and reproducibility

1. Freeze unsupported shielding/CNAPP/parity wording and create immutable source,
   artifact, policy, device, and evidence identities (`CG-MOB-002-E`,
   `CG-CNA-001-A`, `CG-BMK-001-A`).
2. Close signed ingest, anti-replay, tenant boundaries, causal provenance and
   response durability (`CG-MOB-003`, `CG-EDR-001`, `CG-EDR-002`).
3. Establish clean/mobile hostile baselines and quantitative harnesses before
   selecting a transformer or publishing a comparison (`CG-MOB-001-*`,
   `CG-BMK-001-B` through `CG-BMK-001-F`).
4. Close the emulator/simulator/VM-like environment lane as an operational
   App Guard feature: native signal provenance, trusted CI/test exceptions,
   Android/iOS coverage, bypass and clean-device FPR evidence. Existing event
   names alone are not acceptance evidence (`CG-MOB-001-B`, `CG-MOB-001-C`,
   `CG-MOB-001-E`, `CG-MOB-001-F`).
5. Pin canonical event/schema versions and build the connector runtime contract
   without vendor credentials (`CG-SIEM-001-A`, `CG-SIEM-002-A`).

### Next: selected vertical slices

1. Deliver protected-build obfuscation, encryption and provenance slices on one
   Android and one iOS reference app (`CG-MOB-002-A`, `CG-MOB-002-B`).
2. Run category-correct Appdome and Guardsquare XTD protected-build protocols,
   separately from Zimperium/Lookout MTD; report unknowns rather than
   estimating inaccessible results (`CG-MOB-VND-002`, `CG-MOB-VND-003`,
   `CG-MOB-001-D`, `CG-MTD-002-A`, `CG-MTD-002-B`).
3. Complete one endpoint vertical slice from sensor through durable causal
   graph, approval, response outcome, reconciliation and UI evidence on
   Windows and Linux, with macOS explicit as supported or degraded
   (`CG-EDR-001`, `CG-EDR-002`, `CG-EDR-003`).
4. Seal the generic temporal endpoint holdout before any named CrowdStrike,
   SentinelOne, Microsoft Defender or Cortex protocol. Preserve SentinelOne
   rollback as Windows-only in comparisons (`CG-EDR-004-*`, `CG-EDR-VND-*`).
5. Ship loss-aware OCSF/ECS exports and one governed connector at a time:
   Google UDM, Sentinel Logs Ingestion/ASIM, then Elastic ECS
   (`CG-SIEM-001-*`, `CG-SIEM-002-B` through `CG-SIEM-002-E`).
6. Import one CSPM/CIEM/DSPM provider contract and correlate it to endpoint
   evidence (`CG-CNA-001-B` through `CG-CNA-002-B`).

### Later: expensive differentiation

1. Integrate targeted virtualization and rewriting only after the baseline
   identifies high-value regions and an acceptable overhead envelope
   (`CG-MOB-002-C`, `CG-MOB-002-D`).
2. Add MDM/UEM, bidirectional cases and a second CNAPP provider after the shared
   runtime proves replay, rotation, deletion and upgrade behavior.
3. Consider Tamandua-owned virtualization only when the re-entry conditions in
   the decision table are met. A generic binary rewriter and generic SIEM/CNAPP
   remain killed scope.
4. Admit ITDR, exposure management, DLP, enterprise browser/SSE or staffed MDR
   only through the watchlist re-entry conditions; these are integration or
   partner surfaces, not reasons to delay endpoint durability and evidence.

## Quantitative benchmark protocol

All comparative runs use the same source revision, reference workflow, test
accounts, network shaping, device model/OS cohort, warm-up, repetition count,
policy intent and measurement window. Each protected artifact gets a unique
digest and fresh install. Randomization order, failures, unsupported cases,
abstentions and operator interventions are retained. Vendor defaults and tuned
policies are separate cohorts; they must never be merged.

The values below are prospective release-candidate planning targets, not current
results, achieved gates, vendor targets, or evidence of readiness. The
Maintainer may tighten them through a versioned, preregistered benchmark
protocol, but may not silently relax them after seeing results.

Repeated observations from the same app, artifact, device/install, workflow,
malware family, attack technique, or build seed are not independent samples.
Every run must preregister its independent analysis unit and clustering keys.
Intervals are two-sided 95% intervals unless an upper-bound target explicitly
uses a one-sided 95% bound. Cluster bootstrap resamples the highest applicable
independent cluster and preserves paired observations; the run records seed,
resample count (minimum 10,000), and interval method.

| Dimension | Definition and minimum cohort | Planning target (not a result) | Required report |
| --- | --- | --- | --- |
| False-positive rate | `FP / (FP + TN)`. Independent unit is a preregistered clean `app-build x device-install x workflow`; repeated events inside that unit are clustered, not added to the denominator. At least 10,000 independent units, 200 distinct clean apps and 20 device/OS configurations, stratified by OS/framework/policy | blocking-policy one-sided Wilson 95% upper bound `<= 0.10%`; warn/step-up upper bound `<= 0.50%`; zero silent exclusions | FP, TN, denominator, unit definition, cluster keys, Wilson bound plus app/device-cluster bootstrap interval, policy, strata and every FP evidence ID |
| Detection efficacy | `FNR = FN / (TP + FN)` and `TPR = TP / (TP + FN) = 1 - FNR`. Independent unit is one preregistered malicious artifact/scenario objective on a fresh install; variants sharing family/source/campaign are clustered. At least 1,000 independent units and 100 families/scenario groups in the governed holdout | no universal efficacy target is inferred here; a versioned protocol must preregister a cohort-specific TPR lower bound/FNR upper bound before opening the holdout | TP, FN, shared denominator, Wilson interval and family/source/time-cluster bootstrap interval, threshold, abstentions, family/scenario strata and leakage controls |
| Bypass | successful objective completions divided by all valid hostile attempts. Independent unit is one preregistered objective attempt on a fresh install; attempts sharing technique, target artifact or build seed are clustered. At least 30 attempts per technique/build and three fresh-build seeds | 100% attempt accounting; no unresolved P0 bypass for release wording; observed bypass rate and time-to-bypass are always published | successes, failures, denominator, two-sided Wilson binomial interval, technique/artifact/build-cluster bootstrap interval, tool version, preconditions, median/p95 time-to-bypass and evidence outcome |
| Runtime performance | paired unprotected/protected cold and warm observations on the same device/workflow/build seed; at least 30 pairs per Tier-1 configuration. Independent unit is the device/build-seed pair, with repetitions nested inside it | cold-start p95 delta `<= 10%`, steady-state CPU p95 `<= 10%`, PSS/RSS p95 `<= 15%` unless a preregistered exception is approved | raw pairs, paired median and p95 deltas, device/build-cluster bootstrap 95% intervals, seed/resamples, thermal state and profiler version |
| Package/build cost | deterministic clean builds, at least five per policy | artifact size delta `<= 20%`; protected-build p95 duration delta `<= 100%`; reproducibility/provenance gate 100% | input/output digests, symbols, build duration, cache state, signer and manifest |
| Battery/network | paired baseline/protected 24-hour passive and 60-minute active workflows on the same physical device after randomized order/cooldown; at least 10 device pairs per Tier-1 configuration. Independent unit is the physical device/day pair; repeated samples are nested | passive median delta `<= 1` percentage point/24h; active median delta `<= 3` points/hour; added network median `<= 5 MiB/day` | raw pairs, paired median delta, device/day-cluster bootstrap 95% interval, seed/resamples, radio bytes, wakeups, thermal state and background policy |
| Compatibility | A versioned Tier registry, frozen before results, enumerates OS/version, physical model, ABI, framework/runtime, signing/store lane and support window. Minimum: 10 Tier-1 configurations per platform, 20 additional Tier-2 configurations per platform, and 30 critical-workflow trials per configuration; configuration-workflow trial is the denominator | 100% Tier-1 critical trials; `>= 98%` Tier-2 trials; zero protection-attributed P0/P1 crash or data loss | Tier-registry digest, passed/failed/unsupported denominators by configuration/workflow, crash-free sessions, ANR/hang rate, exclusions and regression owner |
| Connector correctness | immutable fixture replay plus governed destination acknowledgement | 100% required-field conformance; zero cross-tenant delivery; duplicate rate `<= 0.01%`; documented loss ledger | sent/accepted/rejected counts, lag p50/p95/p99, retries, dead letters, cursor and destination query evidence |

No vendor comparison may use marketing feature counts as a metric. Lookout MTD,
Zimperium MTD and in-app shielding are different product surfaces; comparisons
must be split into app shielding, device threat posture, intelligence, policy,
integration and operations cohorts.

## EDR evaluation protocol and evidence custody

EDR efficacy work uses a preregistered protocol before any sealed data is
opened. The protocol pins the model, detector/rule set, score orientation,
thresholds, temporal cutoff, independent analysis unit, cluster keys, family
and source strata, abstention policy, success oracle and statistical method.
Training, calibration and holdout identities are disjoint by hash and by the
declared family/source/time clustering keys. Near-duplicates, repacks and
variants cannot cross a split merely because their byte hashes differ.

Every malware or goodware object has an immutable content digest, acquisition
authority, source class, receipt time, label provenance, custody events,
retention/deletion rule and permitted-use decision. Quarantined bytes remain in
an isolated malware store and lab; public evidence contains metadata and
digests, not redistributable binaries. A download candidate, synthetic replay,
bootstrap label or local smoke is not governed corpus membership.

Execution requires written authorization, approved licensing/use, an isolated
runner with no production credentials, controlled egress, disposable state,
operator identity, start/end timestamps, tool versions, logs, rollback and
post-run verification. Invalid, timed-out and excluded attempts remain in the
denominator ledger with reasons. Opening a holdout, changing a threshold after
results, losing custody, or mixing synthetic and physical evidence invalidates
the run; it does not create a weaker publishable result.

Promotion requires an independent reviewer to reproduce the report from the
sealed manifest and raw result bundle, verify split/leakage and custody, and
confirm that public wording does not exceed the evidence class. This protocol
supports scoped Tamandua measurements only; it does not imply vendor parity,
universal malware efficacy or production prevention.

## Reproducible vendor comparison protocols

### Guardsquare: DexGuard/iXGuard

- Scope: the same Android/iOS reference app and sensitive workflows, with an
  unprotected control, Tamandua baseline, and a licensed pinned Guardsquare
  build. Android and iOS remain separate results.
- Configure distinct layers: name/control-flow obfuscation, encryption,
  virtualization, runtime checks and combined policy. Preserve vendor version,
  policy/configuration, protection report, artifact digest and signer.
- Exercise static recovery, strings/resources, decompilation, diffing, patch/
  resign, debugger, hook/instrumentation, root/jailbreak, emulator, MITM and
  clean compatibility. Measure every quantitative dimension above.
- Result class: `vendor_declared` until a licensed artifact is built;
  `governed_lab` only for the exact tested artifact. No generalized parity.

### Zimperium: zDefend and Mobile Threat Defense

- Split zDefend in-app RASP from fleet/device MTD. Do not credit one surface to
  the other. Use the same app workflow for zDefend and the same governed device/
  network threat scenarios for MTD.
- Record SDK/build integration, enabled policy, offline behavior, event latency,
  app/device/network coverage, enforcement, MDM/UEM handoff and evidence export.
- Exercise repackaging, debugger/hook, root/jailbreak, emulator, MITM, malicious/
  risky app and phishing/network scenarios only where the licensed product
  contract supports them. Unsupported remains unsupported.
- Result class follows the same `vendor_declared` to `governed_lab` boundary.

### Lookout Mobile Endpoint Security

- Treat Lookout as a device/fleet threat-posture and intelligence comparison,
  not as proof of binary shielding. Compare enrollment/privacy, app/device/
  network/phishing signals, policy actions, offline/freshness behavior, UEM/zero
  trust integrations, operations and evidence export.
- Bind device identity, OS, enrollment mode, policy, event timestamps and
  downstream acknowledgement. Run managed and BYOD/privacy cohorts separately.
- Compare Tamandua only on overlapping, observed scenarios. Global telemetry,
  intelligence quality and zero-day efficacy remain unknown without independent
  data and must not be inferred from vendor-declared scale.

### Appdome and Guardsquare XTD (formerly Verimatrix)

- Compare both as mobile app shielding/RASP products on the same signed
  reference app; do not treat their declared monitoring or telemetry as
  device-wide MTD or endpoint EDR.
- Appdome cohorts pin the Mobile RASP/App Shielding and binary-obfuscation policy;
  Guardsquare cohorts pin the XTD protection configuration. Each retains the
  input/output digest, build receipt, signer, clean-workflow result, hostile
  attempt ledger and raw performance/power traces.
- A vendor page defines test dimensions only. The result remains blocked until
  license review, artifact custody, physical-lab execution and independent
  review pass for the exact tested build.

### CrowdStrike, SentinelOne, Microsoft Defender and Cortex XDR

- Use one common EDR protocol, but isolated clean snapshots per product so
  sensors cannot interfere. Default and tuned policy cohorts remain separate.
- CrowdStrike pins Falcon platform/endpoint sources and retains available
  detection, incident, raw-event and response receipts. SentinelOne pins
  Singularity XDR/Endpoint and retains available threat, Storyline and response
  receipts. Microsoft separates MDE-only endpoint evidence from Defender XDR
  cross-product correlation. Cortex records exactly which endpoint, network and
  cloud XQL datasets are licensed and present; absent data is `unsupported`,
  never a zero.
- Missed telemetry, missed detection, failed investigation linkage and failed
  response are distinct counters. A dashboard image cannot replace a raw export
  or API receipt. These named protocols reuse `CG-EDR-004-D` measurement and
  `CG-BMK-001-H` through `CG-BMK-001-K` preregistration, custody, review and
  pre-run legal governance; they do not add a second efficacy path. Any named
  public wording remains separately blocked on `CG-BMK-001-L`.

## Canonical SIEM/schema/connector architecture

The Tamandua canonical envelope remains the source record. Versioned adapters
produce OCSF, ECS, Google UDM and Sentinel ASIM/custom-table representations.
Every mapping has source field, destination field, transform, cardinality,
required/optional state, semantic-loss reason, redaction, schema version and
round-trip/replay fixture. Vendor-specific fields use namespaced extensions;
they never silently overwrite canonical values.

Connector lifecycle is `draft -> fixture_validated -> sandbox_validated ->
enabled -> degraded -> disabled -> deprecated -> removed`. Promotion requires
credential validation, least privilege, tenant binding, checkpoint durability,
idempotent replay, rate-limit/backoff, dead letter, lag/error/coverage health,
secret rotation, audit, version upgrade/downgrade and deletion/revocation tests.
Disabling stops new delivery without deleting evidence; removal requires a
retention/export decision.

- Google SecOps: integrate through pinned Chronicle API ingestion methods and
  UDM first. Treat the previous-generation Ingestion API and raw logs as
  migration/fallback paths with explicit parser, deduplication and loss
  contracts. Build Tamandua detections and evidence links; do not rebuild Google
  SecOps storage/search.
- Microsoft Sentinel: use Logs Ingestion API plus DCR/custom table and ASIM
  parser/content. Migrate the legacy HTTP Data Collector connector with dual
  write, count/digest reconciliation, destination-query proof, cutover and
  rollback; never run duplicate legacy and modern feeds indefinitely.
- Elastic Security: emit pinned ECS core fields first, namespaced extensions
  second, and package a versioned Elastic integration with pipeline, mappings,
  dashboards only after fixture conformance. Do not fork ECS semantics.

## CNAPP strategy and scope freeze

The immediate product strategy is integration, not recreation. First inventory
all current UI, API, schema, detector and documentation references that could be
read as CSPM, CIEM, DSPM, cloud graph or CNAPP. Freeze new broad claims and mark
each surface `implemented`, `adapter-only`, `prototype`, `stale`, or `remove`.
Only generated readiness may later lift the freeze.

- CSPM adapter: import configuration/compliance findings, resource identity,
  policy/rule identity, status transitions, remediation and evidence.
- CIEM adapter: import principal/resource/effective-permission findings with
  source confidence and time bounds. Tamandua must not compute "effective"
  access unless the provider evidence supports it.
- DSPM adapter: import datastore/data-classification findings and sensitivity
  labels without ingesting customer content. Classification provenance and
  retention are mandatory.
- Cloud graph: correlate provider nodes/edges to Tamandua identity, workload,
  endpoint, process, network, alert and case entities. Ambiguity creates
  candidates, never a silent merge.
- Provider order: select one of Wiz or Prisma Cloud through customer pull and
  sandbox/API availability; finish the shared provider contract before adding
  the second. Provider results are not Tamandua scanner results.

Reconsider building a narrow cloud control only after three design partners use
the same missing control, provider APIs cannot satisfy it, source telemetry and
maintenance ownership exist, and a quantified build-vs-integrate review passes.
This is not authorization to build a full CNAPP.

## Provider selection, DRI activation and portfolio stops

Tamandua opens one governed destination integration at a time. Elastic is the
default SIEM **candidate** because the repository already has an Elastic
surface and a pinned ECS path; it is not selected, certified or preferred by
evidence. A qualified design partner may select Google SecOps or Sentinel
instead when its existing environment, sandbox access and quantified score are
stronger. Wiz and Prisma Cloud have no default order: the first CNAPP provider
is selected only through partner pull, an existing partner license and usable
read-only sandbox/API access.

Provider selection is scored out of 100: design-partner pull `30`, sandbox/API
and evidence access `20`, canonical mapping reuse `15`, twelve-month TCO `15`,
adoption/distribution fit `10`, and security/operability `10`. Activation needs
`>= 75` and no veto. Vetoes are: no named Tamandua DRI or customer DRI; no
non-production sandbox; no least-privilege tenant binding and credential
revocation; terms that prevent internal evidence retention/review; no
destination acknowledgement/query reconciliation; or no approved TCO cap.
TCO includes loaded engineering, incremental license, infrastructure, API,
egress, support/on-call and compliance costs; existing code is not counted as
saved cost until it passes the selected provider contract.

A DRI activates only after selection. The activation record names the person,
backup, customer counterpart, bounded write scope, capacity, six-week outcome,
escalation path, stop authority and handoff. No provider code starts from an
unowned roadmap row. Target windows are conditional and relative: selection
within five business days after a complete partner packet; DRI activation
before implementation; sandbox pilot within six weeks after activation; and
adoption review after four consecutive pilot weeks. CNAPP selection cannot
start before the shared connector runtime is accepted. The sole calendar
exception is Sentinel legacy handling: inventory is immediate and any active
legacy path must complete its governed migration before the external
`2026-09-14` support deadline.

`defer` applies when no qualified partner, DRI, sandbox, approved TCO or score
exists; reassessment requires new evidence, not elapsed time. A pilot is
`kill`ed when it exceeds eight engineer-weeks before first acknowledged record,
violates tenant isolation, cannot provide durable cursor/idempotency and
revocation, blocks evidence under provider terms, exceeds its TCO cap, or loses
the partner. Expansion is killed when the first integration fails the
four-week adoption gate. A generic SIEM storage/search product, generic CNAPP
scanner/attack-path engine, unbounded parser catalog and simultaneous
multi-provider launch remain outside scope.

## Acceptance and execution-plan matrix

This is the single item registry. Parent IDs remain stable; child IDs may be
retired only with a supersession link. Evidence entries are prospective until
an immutable run exists. `TBD` commands intentionally expose missing harnesses.
Parent rows are scope/claim umbrellas, not shortcuts: `CG-MOB-001` cannot close
before `CG-MOB-001-A` through `CG-MOB-001-F`; `CG-EDR-004` cannot close before
`CG-EDR-004-A` through `CG-EDR-004-D`; and `CG-BMK-001` cannot authorize a
comparison before the applicable measurement children plus
`CG-BMK-001-H` through `CG-BMK-001-L` pass. Mobile named-vendor coordination
also requires the applicable `CG-MOB-VND-*` and MTD-provider receipts. The EDR
generic holdout may close independently, but a named-vendor EDR comparison path
remains open until all four `CG-EDR-VND-*` receipts pass. SIEM/CNAPP parent completion applies
only to the single selected provider and does not promote deferred providers or
create generic SIEM/CNAPP claims.

| Gap ID | Priority | Owner lane | Status | Decision | Dependencies | Acceptance summary | Validation command | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CG-MOB-001` | P0 | Mobile Validation | external-blocked | build evidence | CG-MOB-003, CG-MOB-004, CG-BMK-001 | Governed hostile+clean matrix with artifact/device/policy identity | `python sdk/mobile/scripts/physical_attack_lab_evidence.py --strict` | planned: `docs/benchmarks/runs/mobile_attack_matrix/` |
| `CG-MOB-001-A` | P0 | Mobile Validation | mapped | build | canonical scenarios, devices | Versioned attacks, clean workflows, success oracle and exclusions | `TBD: python tools/mobile_protection/build_scenario_registry.py --strict` | planned: scenario registry + digest |
| `CG-MOB-001-B` | P0 | Mobile Red Team | external-blocked | build | CG-MOB-001-A, signed artifacts | Repeated static/dynamic bypass attempts with full accounting | `TBD: python tools/mobile_protection/run_bypass_matrix.py --manifest <path> --strict` | planned: raw hostile run bundle |
| `CG-MOB-001-C` | P0 | Mobile QA | external-blocked | build | CG-MOB-001-A, tier matrix | Clean FPR, crash, workflow and compatibility denominators meet gates | `TBD: python tools/mobile_protection/run_clean_compatibility.py --manifest <path> --strict` | planned: clean cohort report |
| `CG-MOB-001-D` | P1 | Validation + Procurement | external-blocked | build evidence | CG-MOB-001-B, CG-MOB-001-C, CG-MOB-001-E, CG-MOB-001-F, CG-MOB-VND-001, CG-MOB-VND-002, CG-MOB-VND-003, CG-MOB-VND-004, CG-MTD-002-A, CG-MTD-002-B | Aggregate coordinator closes only with individual shielding receipts and applicable separate device-MTD receipts; categories are never merged | `TBD: python tools/mobile_protection/compare_vendor_runs.py --manifest <path> --strict` | planned: aggregate index referencing individual receipts; no aggregate-only claim |
| `CG-MOB-001-E` | P0 | Mobile Legal + Security | mapped | build evidence | CG-MOB-001-A, provider/tool licenses, lab authorization | Each hostile scenario has permitted-use/EULA review, written authorization, bounded operator scope and stop conditions before execution | `TBD: python tools/mobile_protection/mobile_lab_authorization_gate.py --manifest <path> --strict` | planned: authorization/license packet; target before any hostile run |
| `CG-MOB-001-F` | P0 | Mobile Evidence Custody | mapped | build evidence | CG-MOB-001-E, CG-MOB-002-E, isolated evidence store | Input/output/device/policy identities, custody events, sanitization, retention, rollback and reviewer receipt form one hash-bound chain | `TBD: python tools/mobile_protection/mobile_evidence_custody_gate.py --manifest <path> --strict` | planned: custody/retention ledger; target with every lab packet |
| `CG-MOB-VND-001` | P1 | Mobile Validation + Procurement | external-blocked | build evidence | CG-MOB-001-B, CG-MOB-001-C, CG-MOB-001-E, CG-MOB-001-F, CG-MOB-002-E, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed Guardsquare artifacts, governed physical-device lab | Pinned DexGuard/iXGuard and Tamandua builds run the same authorized static/dynamic and clean workflows with separate Android/iOS denominators | `TBD: python tools/mobile_protection/compare_vendor_runs.py --vendor guardsquare --manifest <path> --strict` | planned: `docs/benchmarks/runs/mobile_vendor/guardsquare/<run-id>/protocol-receipt.json` |
| `CG-MOB-VND-002` | P1 | Mobile Validation + Procurement | external-blocked | build evidence | CG-MOB-001-B, CG-MOB-001-C, CG-MOB-001-E, CG-MOB-001-F, CG-MOB-002-E, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed Appdome artifact, governed physical-device lab | Pinned protected build and Tamandua build run the same authorized shielding, compatibility and workflow protocol without inferring no-code parity | `TBD: python tools/mobile_protection/compare_vendor_runs.py --vendor appdome --manifest <path> --strict` | planned: `docs/benchmarks/runs/mobile_vendor/appdome/<run-id>/protocol-receipt.json` |
| `CG-MOB-VND-003` | P1 | Mobile Validation + Procurement | external-blocked | build evidence | CG-MOB-001-B, CG-MOB-001-C, CG-MOB-001-E, CG-MOB-001-F, CG-MOB-002-E, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed Guardsquare XTD artifact, governed physical-device lab | Pinned Guardsquare XTD/Tamandua builds run the same authorized runtime-integrity, clean-workflow and platform protocol; reverse-engineering observations alone are excluded | `TBD: python tools/mobile_protection/compare_vendor_runs.py --vendor verimatrix-xtd --manifest <path> --strict` | planned: `docs/benchmarks/runs/mobile_vendor/verimatrix-xtd/<run-id>/protocol-receipt.json`; `verimatrix-xtd` is the historical compatibility alias |
| `CG-MOB-VND-004` | P1 | Mobile Validation + Procurement | external-blocked | build evidence | CG-MOB-001-B, CG-MOB-001-C, CG-MOB-001-E, CG-MOB-001-F, CG-MOB-002-E, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed Zimperium zDefend artifact, governed physical-device lab | zDefend in-app RASP and Tamandua use the same app/workflows and remain distinct from Zimperium fleet/device MTD evidence | `TBD: python tools/mobile_protection/compare_vendor_runs.py --vendor zimperium-zdefend --manifest <path> --strict` | planned: `docs/benchmarks/runs/mobile_vendor/zimperium-zdefend/<run-id>/protocol-receipt.json` |
| `CG-MOB-002` | P1 | Mobile Build Protection | mapped | hybrid | CG-MOB-001, CG-MOB-004 | Policy-controlled protected build with measured transformations | `python sdk/mobile/scripts/validate_sdk_release_contract.py` | planned: protected-build manifest |
| `CG-MOB-002-A` | P1 | Android/iOS Build | mapped | hybrid | CG-MOB-001-A, CG-MOB-002-E, reference apps/symbols | Name/control-flow/native obfuscation verified without critical regression | `TBD: python tools/mobile_protection/verify_obfuscation.py --manifest <path> --strict` | planned: symbol/decompiler/diff evidence |
| `CG-MOB-002-B` | P1 | Mobile Crypto + Build | mapped | hybrid | CG-MOB-001-A, CG-MOB-002-E, key contract/asset allowlist | Selected strings/resources/data protected; no embedded durable secrets | `TBD: python tools/mobile_protection/verify_encryption.py --manifest <path> --strict` | planned: extraction/runtime/rotation evidence |
| `CG-MOB-002-C` | P2 | Mobile Build Protection | mapped | integrate | CG-MOB-001-B, CG-MOB-002-E, CG-BMK-001-D, licensed transformer | Targeted virtualized regions retain semantics and overhead gates | `TBD: python tools/mobile_protection/verify_virtualization.py --manifest <path> --strict` | planned: region/provenance/perf/bypass report |
| `CG-MOB-002-D` | P2 | Mobile Build Protection | mapped | integrate | CG-MOB-001-C, CG-MOB-002-E, signed post-build lane | Rewriting is deterministic, signable, rollback-safe and compatible | `TBD: python tools/mobile_protection/verify_rewriting.py --manifest <path> --strict` | planned: semantic/diff/signing report |
| `CG-MOB-002-E` | P0 | Mobile Release + Supply Chain | active | build | immutable build inputs | Signed manifest binds source, policy, toolchain, input/output, signer, SBOM | `python sdk/mobile/scripts/validate_sdk_release_contract.py` | planned: provenance + attestation bundle |
| `CG-MOB-003` | P0 | Mobile + Server Identity | active | hybrid | enrollment, attestation | Signed ingest, anti-replay, remote policy rollout/rollback fail closed | `python sdk/mobile/scripts/validate_contracts.py` | local contracts only; governed E2E pending |
| `CG-MOB-003-A` | P0 | Mobile Identity | active | hybrid | Play Integrity, App Attest | Hardware/platform proof bound to tenant/app/build/device and freshness | `TBD: python tools/detection_validation/scripts/mobile_attestation_e2e.py --strict` | planned: physical proof bundle |
| `CG-MOB-003-B` | P0 | Server Ingest | active | build | durable nonce/sequence | Duplicate, reorder, expiry, revocation and cross-tenant replay rejected | `TBD: python tools/detection_validation/scripts/mobile_signed_ingest_e2e.py --strict` | planned: PostgreSQL replay report |
| `CG-MOB-003-C` | P0 | Policy Platform | active | build | policy signing, device ack | Versioned audience rollout, cached fallback, ack, rollback and kill switch | `TBD: python tools/detection_validation/scripts/mobile_policy_rollout_e2e.py --strict` | planned: rollout/rollback evidence |
| `CG-MOB-004` | P0 | Mobile Release | external-blocked | hybrid | native runners, signing | Clean-room consume/archive/install/upgrade/rollback exact artifacts | `python sdk/mobile/scripts/validate_sdk_release_contract.py` | local contract; native release evidence pending |
| `CG-EDR-001` | P0 | Detection + Data Platform | active | build | RLS, event identity | Durable tenant-safe causal graph converges across replay/restart/nodes | `TBD: python tools/detection_validation/scripts/causal_graph_e2e.py --postgres --multinode --strict` | planned: graph convergence bundle |
| `CG-EDR-002` | P0 | Response + Platform Security | active | build | outbox, idempotency, RBAC | Durable intent, execution revalidation, reconciliation, outcome and rollback | `python tools/response_validation/harness.py` | local harness; multinode evidence pending |
| `CG-EDR-003` | P0 | Agent Runtime + Release | external-blocked | build | signed OS lanes | Windows/Linux/macOS capability, install/update/rollback/health matrix | `TBD: python tools/detection_validation/scripts/cross_platform_release_gate.py --strict` | generated parity queue + planned OS bundles |
| `CG-EDR-004` | P0 | Detection Validation + ML | hold | build evidence | temporal holdout, provenance | Generic FPR/FNR/latency/cost holdout closes through A-D; any named-vendor path additionally requires CG-EDR-VND-001 through CG-EDR-VND-004 | `python tools/detection_validation/scripts/benchmark_claim_maturity_gate.py` | governed generic holdout unopened; vendor receipts remain separate |
| `CG-EDR-004-A` | P0 | Dataset Governance + Legal | active | build evidence | acquisition authority, immutable hashes, label provenance | Every accepted malware/goodware object has permitted use, source/label provenance, custody, retention and deletion state; candidates are excluded | `TBD: python tools/detection_validation/scripts/corpus_legal_custody_gate.py --strict` | planned: accepted-corpus authority and custody ledger |
| `CG-EDR-004-B` | P0 | ML Validation | hold | build evidence | CG-EDR-004-A, family/source/time clustering | Temporal train/calibration/holdout manifests are sealed, near-duplicate/family leakage is zero and opening requires an authorization receipt | `TBD: python tools/detection_validation/scripts/sealed_temporal_holdout_gate.py --strict` | planned: sealed split manifest and leakage report |
| `CG-EDR-004-C` | P0 | Malware Lab + Security | external-blocked | build evidence | CG-EDR-004-A, CG-EDR-004-B, isolated runners | Authorized disposable runners enforce isolation, controlled egress, no production credentials, attempt accounting, rollback and post-run verification | `TBD: python tools/detection_validation/scripts/malware_lab_execution_gate.py --strict` | planned: governed execution/custody bundle |
| `CG-EDR-004-D` | P0 | Detection Validation + Independent Review | hold | build evidence | CG-EDR-004-B, CG-EDR-004-C, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J | Frozen model/threshold report reproduces FPR/FNR/calibration/latency/cost with clustered intervals and independent sign-off | `TBD: python tools/detection_validation/scripts/edr_holdout_evaluation_gate.py --strict` | planned: reproducible holdout report; no claim before review |
| `CG-EDR-VND-001` | P1 | EDR Validation + Procurement | external-blocked | build evidence | CG-EDR-001, CG-EDR-002, CG-EDR-003, CG-EDR-004-D, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed CrowdStrike environment, governed endpoint lab | Pinned CrowdStrike and Tamandua configurations run one preregistered endpoint protocol with identical cohorts/oracles and vendor-specific limitations | `TBD: python tools/detection_validation/scripts/edr_vendor_protocol_gate.py --vendor crowdstrike --manifest <path> --strict` | planned: `docs/benchmarks/runs/edr_vendor/crowdstrike/<run-id>/protocol-receipt.json` |
| `CG-EDR-VND-002` | P1 | EDR Validation + Procurement | external-blocked | build evidence | CG-EDR-001, CG-EDR-002, CG-EDR-003, CG-EDR-004-D, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed SentinelOne environment, governed endpoint lab | Pinned SentinelOne and Tamandua configurations run one preregistered endpoint protocol with identical cohorts/oracles and vendor-specific limitations | `TBD: python tools/detection_validation/scripts/edr_vendor_protocol_gate.py --vendor sentinelone --manifest <path> --strict` | planned: `docs/benchmarks/runs/edr_vendor/sentinelone/<run-id>/protocol-receipt.json` |
| `CG-EDR-VND-003` | P1 | EDR Validation + Procurement | external-blocked | build evidence | CG-EDR-001, CG-EDR-002, CG-EDR-003, CG-EDR-004-D, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed Microsoft Defender for Endpoint environment, governed endpoint lab | Pinned MDE and Tamandua configurations run one preregistered endpoint protocol with identical cohorts/oracles and vendor-specific limitations | `TBD: python tools/detection_validation/scripts/edr_vendor_protocol_gate.py --vendor mde --manifest <path> --strict` | planned: `docs/benchmarks/runs/edr_vendor/mde/<run-id>/protocol-receipt.json` |
| `CG-EDR-VND-004` | P1 | EDR Validation + Procurement | external-blocked | build evidence | CG-EDR-001, CG-EDR-002, CG-EDR-003, CG-EDR-004-D, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed Cortex environment, governed endpoint lab | Pinned Cortex and Tamandua configurations run one preregistered endpoint protocol with identical cohorts/oracles and vendor-specific limitations | `TBD: python tools/detection_validation/scripts/edr_vendor_protocol_gate.py --vendor cortex --manifest <path> --strict` | planned: `docs/benchmarks/runs/edr_vendor/cortex/<run-id>/protocol-receipt.json` |
| `CG-EDR-005` | P1 | Control Plane + SRE | active | build | queues, health, RLS | Fleet scale, isolation, backpressure, recovery and cost measured | `python tools/detection_validation/scripts/fleet_scale_isolation_fixture_probe.py` | fixture only; live scale gate pending |
| `CG-SIEM-001` | P1 | Data Platform + Integrations | mapped | build | canonical envelope | Versioned loss-aware OCSF/ECS mapping and compatibility lifecycle | `TBD: python tools/interoperability/validate_security_schema_exports.py --strict` | planned: schema conformance bundle |
| `CG-SIEM-001-A` | P0 | Data Platform | active | build | canonical event IDs | Registry pins canonical, OCSF, ECS, UDM and ASIM versions | `python tools/interoperability/validate_schema_registry.py --strict` | `smoke_local`: 5-entry pinned registry; external conformance remains planned |
| `CG-SIEM-001-B` | P1 | Data Platform | mapped | build | CG-SIEM-001-A | OCSF fixtures cover endpoint/mobile/response/identity/cloud classes | `TBD: python tools/interoperability/validate_ocsf_exports.py --strict` | planned: OCSF fixtures + loss ledger |
| `CG-SIEM-001-C` | P1 | Data Platform | mapped | build | CG-SIEM-001-A | ECS core-first fixtures and namespaced extensions conform | `TBD: python tools/interoperability/validate_ecs_exports.py --strict` | planned: ECS fixtures + loss ledger |
| `CG-SIEM-001-D` | P1 | Data Platform QA | mapped | build evidence | CG-SIEM-001-B, CG-SIEM-001-C | Upgrade/downgrade, unknown fields, round-trip and supersession tested | `TBD: python tools/interoperability/schema_compatibility_gate.py --strict` | planned: compatibility matrix |
| `CG-SIEM-002` | P1 | SecOps + Integrations | mapped | integrate | CG-SIEM-001, secrets | Governed connectors preserve tenant/evidence identity through lifecycle | `TBD: python tools/integrations/connector_contract_gate.py --connector <id> --strict` | planned: per-connector run bundles |
| `CG-SIEM-002-A` | P1 | Integration Platform | mapped | build | CG-SIEM-SEL-002, CG-SIEM-DRI-001, durable cursors/vault | Selected-provider runtime handles lease, cursor, retry, DLQ, rotation, health and audit without becoming a generic SIEM | `TBD: python tools/integrations/connector_runtime_gate.py --strict` | planned: owner-death/replay/rotation report; activate only after selection |
| `CG-SIEM-002-B` | P1 | Google SecOps Integration | mapped | defer | CG-SIEM-SEL-002, CG-SIEM-002-A, Google UDM mapping | If Google is selected, UDM ingestion is acknowledged and destination queries reconcile counts/digests; otherwise no implementation starts | `TBD: python tools/integrations/google_secops_gate.py --strict` | deferred unless selection record chooses Google SecOps |
| `CG-SIEM-002-C` | P1 | Sentinel Integration | mapped | defer | CG-SIEM-SEL-002, CG-SIEM-002-A, DCR/ASIM mapping | If Sentinel is selected, Logs Ingestion/DCR/custom table plus ASIM parser and health pass; otherwise no implementation starts | `TBD: python tools/integrations/sentinel_logs_ingestion_gate.py --strict` | deferred unless selection or legacy inventory chooses Sentinel |
| `CG-SIEM-002-D` | P1 | Sentinel Migration | mapped | defer | CG-SIEM-LEG-001, CG-SIEM-002-A, CG-SIEM-002-C, active legacy credentials | For an inventoried active legacy tenant, dual-write, reconciliation, cutover, rollback and credential revocation complete before `2026-09-14` | `TBD: python tools/integrations/sentinel_legacy_migration_gate.py --strict` | conditional migration/cutover packet; otherwise deferred |
| `CG-SIEM-002-E` | P1 | Elastic Integration | mapped | defer | CG-SIEM-SEL-002, CG-SIEM-002-A, CG-SIEM-001-C | If the default candidate is selected, a versioned package/pipeline maps ECS and survives install/upgrade/replay; candidate status is not selection | `TBD: python tools/integrations/elastic_package_gate.py --strict` | deferred pending scored selection and partner sandbox |
| `CG-SIEM-002-F` | P2 | SecOps Integrations | mapped | defer | CG-SIEM-PILOT-001, connector identity/RBAC | Deep links and case/ack references sync idempotently for the selected provider where supported | `TBD: python tools/integrations/case_evidence_link_gate.py --connector <selected> --strict` | deferred until selected-provider pilot passes |
| `CG-SIEM-SEL-001` | P1 | Growth + Integration Platform | mapped | build evidence | CG-SIEM-001-A, CG-BMK-001-A, complete design-partner packet | Partner has production destination, customer DRI, non-prod sandbox, least privilege, representative data, evidence permission and approved TCO inputs | `TBD: python tools/product_selection/qualify_design_partner.py --surface siem --manifest <path> --strict` | planned: partner qualification; target before provider scoring |
| `CG-SIEM-SEL-002` | P1 | Product + Finance + Security | mapped | build evidence | CG-SIEM-SEL-001, scored provider evidence | Exactly one provider scores at least 75/100 with no veto and approved TCO; Elastic is only the default candidate and overrides are recorded | `TBD: python tools/product_selection/provider_score_gate.py --surface siem --candidates elastic,google_secops,sentinel --strict` | planned: signed selection/defer record; target within five business days of complete packet |
| `CG-SIEM-DRI-001` | P1 | Integration Platform Management | mapped | build evidence | CG-SIEM-SEL-002, named customer counterpart | Named DRI and backup have capacity, bounded scope, six-week outcome, escalation, stop authority, handoff and customer DRI before code starts | `TBD: python tools/product_selection/dri_activation_gate.py --gap CG-SIEM-PILOT-001 --strict` | planned: DRI activation receipt; target before implementation |
| `CG-SIEM-PILOT-001` | P1 | Selected SIEM Integration | external-blocked | integrate | CG-SIEM-DRI-001, CG-SIEM-002-A, selected schema mapping, partner sandbox | One selected destination passes 14-day reconciliation, zero cross-tenant delivery, duplicate `<= 0.01%`, lag reporting, replay, DLQ, rotation, deletion and upgrade | `TBD: python tools/integrations/selected_siem_pilot_gate.py --provider <selected> --strict` | planned: governed sandbox bundle; target within six weeks of DRI activation |
| `CG-SIEM-ADOPT-001` | P1 | Growth + Design Partner | external-blocked | build evidence | CG-SIEM-PILOT-001, four consecutive pilot weeks | Partner uses the connector in at least two real analyst workflows per week, unresolved P0/P1 is zero and measured support/TCO remains inside cap | `TBD: python tools/product_selection/adoption_gate.py --surface siem --provider <selected> --window-days 28 --strict` | planned: adoption/TCO report; target after four pilot weeks |
| `CG-SIEM-EXP-001` | P2 | Product + Integrations | mapped | defer | CG-SIEM-ADOPT-001, two qualified partner requests, at least 80% runtime reuse | A second SIEM may be selected only after first-provider adoption passes and a separately funded DRI is activated | `TBD: python tools/product_selection/provider_expansion_gate.py --surface siem --strict` | deferred; kill when first-provider adoption fails |
| `CG-SIEM-LEG-001` | P0 | Sentinel Integration + Operations | mapped | build evidence | read-only tenant/config inventory, SRC-MS-MIG-001 | Immediate inventory proves active legacy Data Collector use; active tenants get owner/cutover/rollback before `2026-09-14`, absence keeps migration deferred | `TBD: python tools/integrations/sentinel_legacy_inventory_gate.py --strict` | planned: immediate inventory and conditional deadline-bound migration decision |
| `CG-MTD-001` | P1 | Mobile + Policy | active | build | CG-MOB-001, CG-MOB-003 | Explainable device/session policy with platform-legal silent behavior | `TBD: python tools/mobile_protection/mobile_policy_enforcement_e2e.py --strict` | planned: policy/FPR/latency/battery report |
| `CG-MTD-001-A` | P1 | Mobile Detection | active | build | native signals, privacy | Versioned app/device/network posture with freshness and confidence | `TBD: python tools/mobile_protection/mobile_posture_gate.py --strict` | planned: posture coverage matrix |
| `CG-MTD-001-B` | P1 | Mobile Policy | active | build | CG-MTD-001-A, server policy | allow/observe/warn/step-up/block/session-kill decisions audited | `TBD: python tools/mobile_protection/mobile_decision_gate.py --strict` | planned: decision/audit bundle |
| `CG-MTD-002` | P2 | Integrations + Mobile | mapped | integrate | CG-SIEM-002-A, device identity | Provider/UEM adapters reconcile identity, freshness, audit and retention | `TBD: python tools/integrations/mobile_provider_contract_gate.py --provider <id> --strict` | planned: provider sandbox bundle |
| `CG-MTD-002-A` | P2 | Zimperium Integration | external-blocked | integrate | CG-MTD-002, CG-MOB-001-C, CG-MOB-001-E, CG-MOB-001-F, CG-MOB-VND-004, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed sandbox, governed physical-device lab | zDefend shielding receipt and device-MTD receipt remain separate; device/app/network policy, privacy, custody and clean controls are measured without category transfer | `TBD: python tools/integrations/zimperium_contract_gate.py --strict` | planned: `docs/benchmarks/runs/mobile_mtd/zimperium/<run-id>/protocol-receipt.json` |
| `CG-MTD-002-B` | P2 | Lookout Integration | external-blocked | integrate | CG-MTD-002, CG-MOB-001-C, CG-MOB-001-E, CG-MOB-001-F, CG-BMK-001-A, CG-BMK-001-H, CG-BMK-001-I, CG-BMK-001-J, CG-BMK-001-K, licensed sandbox, governed physical-device lab | Device/app/network/phishing posture, privacy, UEM lifecycle, custody and clean controls are measured only on supported licensed scenarios | `TBD: python tools/integrations/lookout_contract_gate.py --strict` | planned: `docs/benchmarks/runs/mobile_mtd/lookout/<run-id>/protocol-receipt.json` |
| `CG-MTD-002-C` | P2 | UEM Integration | mapped | integrate | CG-MTD-002, device reconciliation | One selected Intune/Jamf/Workspace ONE adapter passes lifecycle | `TBD: python tools/integrations/uem_contract_gate.py --provider <id> --strict` | planned: UEM sandbox evidence |
| `CG-CNA-001` | P2 | Cloud Integrations | mapped | defer | CG-CNA-SEL-001, CG-CNA-DRI-001, CG-SIEM-002-A | One partner-selected provider imports normalized CSPM/CIEM/DSPM metadata; no provider is implemented before activation | `TBD: python tools/integrations/cnapp_finding_contract_gate.py --provider <selected> --strict` | deferred pending qualified partner, provider selection and sandbox |
| `CG-CNA-001-A` | P0 | Product + Release Claims | active | build evidence | repo/UI/API inventory | Audit/freeze classifies own CNAPP surface and blocks unsupported wording | `python tools/product_audit/cnapp_surface_freeze.py --strict` | `smoke_local`: deterministic 36/36 source/content inventory; not runtime evidence |
| `CG-CNA-001-B` | P2 | Cloud Integrations | mapped | integrate | CG-CNA-PILOT-001, provider account binding | Selected-provider CSPM configuration/compliance finding lifecycle converges | `TBD: python tools/integrations/cspm_contract_gate.py --provider <selected> --strict` | planned: selected-provider CSPM fixture+sandbox evidence |
| `CG-CNA-001-C` | P2 | Identity + Cloud | mapped | integrate | CG-CNA-PILOT-001, identity resolver | Selected-provider CIEM principal/resource/effective-permission provenance is retained without silent identity merges | `TBD: python tools/integrations/ciem_contract_gate.py --provider <selected> --strict` | planned: selected-provider CIEM identity/permission evidence |
| `CG-CNA-001-D` | P2 | Data Security + Privacy | mapped | integrate | CG-CNA-PILOT-001, classification/privacy policy | Selected-provider DSPM sensitivity metadata is imported without customer data content | `TBD: python tools/integrations/dspm_contract_gate.py --provider <selected> --strict` | planned: selected-provider DSPM privacy/provenance evidence |
| `CG-CNA-001-E` | P2 | Cloud Integrations + SRE | mapped | build | CG-CNA-PILOT-001, provider schemas | Create/update/delete/reopen, cursor, rotation, lag and health pass for the selected provider | `TBD: python tools/integrations/cnapp_lifecycle_gate.py --provider <selected> --strict` | planned: selected-provider lifecycle/health report |
| `CG-CNA-SEL-001` | P2 | Growth + Cloud Integrations | mapped | defer | CG-CNA-001-A, CG-SIEM-002-A, existing partner license, complete design-partner packet | One partner with licensed Wiz or Prisma passes qualification and exactly one provider scores at least 75/100 with no veto and approved TCO; no default provider | `TBD: python tools/product_selection/provider_score_gate.py --surface cnapp --candidates wiz,prisma --partner-manifest <path> --strict` | deferred until shared runtime and partner packet exist; then score within five business days |
| `CG-CNA-DRI-001` | P2 | Cloud Integrations Management | mapped | defer | CG-CNA-SEL-001, provider score at least 75 with no veto | Named DRI and backup have capacity, exact provider/scope, six-week outcome, customer DRI, escalation and stop authority before adapter code starts | `TBD: python tools/product_selection/dri_activation_gate.py --gap CG-CNA-PILOT-001 --strict` | deferred; target before implementation after partner-led selection |
| `CG-CNA-PILOT-001` | P2 | Selected CNAPP Integration | external-blocked | integrate | CG-CNA-DRI-001, CG-SIEM-002-A, partner sandbox, provider schemas | One selected provider passes finding create/update/resolve/reopen, identity/resource provenance, cursor/replay/rotation/retention and metadata-only privacy | `TBD: python tools/integrations/cnapp_finding_contract_gate.py --provider <selected> --strict` | planned: governed partner sandbox bundle; target within six weeks of DRI activation |
| `CG-CNA-ADOPT-001` | P2 | Growth + Design Partner | external-blocked | build evidence | CG-CNA-PILOT-001, four consecutive pilot weeks | Partner uses imported evidence in at least two analyst workflows weekly, including one accepted cloud-to-endpoint investigation, with no unresolved P0/P1 and TCO inside cap | `TBD: python tools/product_selection/adoption_gate.py --surface cnapp --provider <selected> --window-days 28 --strict` | planned: adoption/TCO report; target after four pilot weeks |
| `CG-CNA-EXP-001` | P2 | Product + Cloud Integrations | mapped | defer | CG-CNA-ADOPT-001, two distinct qualified partner requests, at least 80% runtime/adapter reuse | A second CNAPP provider may start only after first-provider adoption and separately funded DRI activation | `TBD: python tools/product_selection/provider_expansion_gate.py --surface cnapp --strict` | deferred; kill when first-provider adoption fails |
| `CG-CNA-002` | P2 | Graph + Investigations | mapped | hybrid | CG-CNA-001, CG-EDR-001 | Provider cloud evidence correlates to endpoint without silent merges | `TBD: python tools/detection_validation/scripts/cloud_endpoint_graph_e2e.py --strict` | planned: graph scenario bundle |
| `CG-CNA-002-A` | P2 | Graph Platform | mapped | build | CG-CNA-001, canonical cloud identities | Nodes/edges retain provider, confidence, valid time and ambiguity | `TBD: python tools/detection_validation/scripts/cloud_graph_contract_gate.py --strict` | planned: graph contract fixtures |
| `CG-CNA-002-B` | P2 | Detection + Graph | mapped | build | CG-CNA-002-A, CG-EDR-001 | Governed workload/identity/endpoint/process scenarios correlate | `TBD: python tools/detection_validation/scripts/cloud_endpoint_correlation_gate.py --strict` | planned: correlation precision report |
| `CG-CNA-002-C` | P2 | Investigations | mapped | build | CG-CNA-002-B, RBAC | Analyst sees provenance, confidence, missing evidence and corrections | `TBD: python tools/detection_validation/scripts/cloud_investigation_ux_gate.py --strict` | planned: investigation/audit evidence |
| `CG-BMK-001` | P1 | Validation + Maintainer | mapped | build evidence | immutable runs, authorities | Scorecard states denominator/environment/class/command/digest/limits | `python tools/detection_validation/scripts/benchmark_claim_maturity_gate.py` | generated authority remains controlling |
| `CG-BMK-001-A` | P0 | Competitive Research | active | build evidence | official sources, version/date | Source registry distinguishes vendor_declared from observed evidence | `python tools/detection_validation/scripts/competitive_source_registry_gate.py --strict` | `source_review`: 35-source structural registry; governed readiness correctly blocked |
| `CG-BMK-001-B` | P0 | Validation Statistics | mapped | build evidence | clean cohort | FPR/FNR with denominators, strata and Wilson 95% intervals | `TBD: python tools/detection_validation/scripts/competitive_fpr_gate.py --strict` | planned: raw labels + statistical report |
| `CG-BMK-001-C` | P0 | Mobile Red Team | external-blocked | build evidence | hostile harness, fresh builds | Bypass rate, attempt accounting and time-to-bypass reproducible | `TBD: python tools/detection_validation/scripts/competitive_bypass_gate.py --strict` | planned: hostile transcripts/artifacts |
| `CG-BMK-001-D` | P1 | Performance | external-blocked | build evidence | profilers, paired builds | Startup/CPU/memory/package/build metrics meet protocol | `TBD: python tools/detection_validation/scripts/competitive_performance_gate.py --strict` | planned: raw profiler traces |
| `CG-BMK-001-E` | P1 | Mobile Performance | external-blocked | build evidence | physical battery lab | Passive/active battery, radio, wakeup and thermal metrics measured | `TBD: python tools/detection_validation/scripts/competitive_battery_gate.py --strict` | planned: energy/raw device bundle |
| `CG-BMK-001-F` | P0 | Mobile QA | external-blocked | build evidence | Tier matrix, signed builds | OS/ABI/framework/install/upgrade/rollback/workflow coverage reported | `TBD: python tools/detection_validation/scripts/competitive_compatibility_gate.py --strict` | planned: compatibility matrix |
| `CG-BMK-001-G` | P1 | Maintainer + Claims | mapped | build evidence | CG-BMK-001-A through CG-BMK-001-F | Stale/conflicting evidence fails; public copy cannot exceed authority | `python tools/detection_validation/scripts/refresh_validation_authority.py --dry-run` | generated scorecard/readiness after owned refresh |
| `CG-BMK-001-H` | P0 | Validation Protocol | mapped | build evidence | CG-BMK-001-A, frozen cohort definitions | Protocol preregisters independent unit, clusters, thresholds, exclusions, oracles, intervals and promotion wording before data or holdout access | `TBD: python tools/detection_validation/scripts/benchmark_preregistration_gate.py --strict` | planned: immutable preregistration digest |
| `CG-BMK-001-I` | P0 | Evidence Governance | mapped | build evidence | CG-BMK-001-H, source/artifact identities, retention policy | Every input, tool, output, exclusion and custody transfer is hash-bound with permitted use, retention, deletion and supersession state | `TBD: python tools/detection_validation/scripts/benchmark_custody_gate.py --strict` | planned: benchmark custody and exclusion ledger |
| `CG-BMK-001-J` | P0 | Independent Validation | external-blocked | build evidence | CG-BMK-001-H, CG-BMK-001-I, completed raw run bundle | Independent reviewer reproduces denominators/statistics/digests, confirms limitations and signs a result that cannot exceed its evidence class | `TBD: python tools/detection_validation/scripts/independent_benchmark_review_gate.py --strict` | planned: reviewer reproduction/sign-off packet |
| `CG-BMK-001-K` | P0 | Legal + Procurement | mapped | build evidence | CG-BMK-001-A, CG-BMK-001-H, pinned vendor source/version, license/terms review | Before artifact access or execution, EULA/license, benchmark-publication permission, permitted use, lab authorization, retention and disclosure constraints are approved | `TBD: python tools/detection_validation/scripts/benchmark_legal_permitted_use_gate.py --manifest <path> --strict` | planned: vendor-specific pre-run legal/permitted-use receipt |
| `CG-BMK-001-L` | P0 | Legal + Release Claims | hold | build evidence | CG-BMK-001-J, CG-BMK-001-K, CG-BMK-001-G, applicable vendor protocol receipt | Final named-public wording pins tested versions/artifacts, discloses method/limits, matches independent evidence and has explicit legal plus human release approval | `TBD: python tools/detection_validation/scripts/benchmark_public_claim_approval_gate.py --manifest <path> --strict` | planned: vendor-specific final public-claim approval receipt; no approval by aggregation |

## TBD harness promotion plan (priority lanes)

Added 2026-07-21. This section changes nothing in the acceptance matrix above
and creates no claim. For each `TBD:`-command item in the three top-priority
comparison lanes, it records either the concrete verification command that
already exists and runs today (a precursor, never a substitute for the item's
own missing harness) or the minimal evidence artifact whose existence would
move the item exactly one class up the ordered evidence scale
(`source_review < smoke_local < synthetic_parity < governed_lab <
governed_holdout < production_telemetry < independent_validation`). Running a
precursor command does not close an item and does not change its matrix
status; only the item's own acceptance command plus recorded evidence does.

### Lane A: mobile shielding (Guardsquare and Appdome comparison lanes)

- `CG-MOB-001-A` (`source_review -> smoke_local`): commit a versioned
  scenario-registry v1 (scenario IDs, success oracle, exclusion rules,
  SHA-256 digest) seeded from the scenario set already exercised by
  `python sdk/mobile/scripts/native_compromise_rehearsal.py`.
- `CG-MOB-001-B` (`smoke_local -> governed_lab`): minimal artifact is one
  hostile attempt ledger for a single technique on one physical device with
  full attempt accounting; existing device-side precursor:
  `python tools/detection_validation/scripts/mobile_app_guard_adb_smoke_probe.py`.
- `CG-MOB-001-C` (`source_review -> smoke_local`): pin the clean-app cohort
  manifest produced by
  `python sdk/mobile/scripts/android_clean_goodware_candidates.py` with
  digests and device tiers before quoting any FPR denominator.
- `CG-MOB-001-D`: aggregate coordinator with no promotion path of its own;
  next artifact is a receipt-index schema draft. It stays open until the
  applicable `CG-MOB-VND-*` and MTD receipts exist.
- `CG-MOB-001-E` (`source_review -> smoke_local`): complete the per-scenario
  permitted-use/authorization record for the first Android hostile scenario;
  no hostile execution may precede this record.
- `CG-MOB-001-F` (`source_review -> smoke_local`): produce one hash-bound
  custody ledger for an existing physical-development packet; packet shape is
  already checkable via
  `python sdk/mobile/scripts/physical_attack_lab_evidence.py --strict`.
- `CG-MOB-002-A` (`source_review -> smoke_local`): before/after symbol and
  decompiler diff on the reference app; existing precursors:
  `python sdk/mobile/scripts/android_hardening_suite.py` and
  `python sdk/mobile/scripts/app_guard_hardening_claims.py`.
- `CG-MOB-002-B` (`source_review -> smoke_local`): string/resource extraction
  diff between protected and unprotected builds of the same commit, with the
  key contract recorded in the release manifest already checked by
  `python sdk/mobile/scripts/validate_sdk_release_contract.py`.
- `CG-MOB-003-A` (`smoke_local -> governed_lab`): one physical-device Play
  Integrity / App Attest verdict bound to tenant, app, build and freshness
  window; contract-shape precursor:
  `python sdk/mobile/scripts/validate_contracts.py`.
- `CG-MOB-003-B` (`smoke_local -> synthetic_parity`): PostgreSQL-backed
  replay-rejection report (duplicate, reorder, expiry, cross-tenant);
  existing precursors:
  `python sdk/mobile/scripts/local_signed_event_rehearsal.py` and
  `python sdk/mobile/scripts/local_ingestion_rehearsal.py`.
- `CG-MOB-003-C` (`smoke_local -> synthetic_parity`): a rollout/ack/rollback
  trace for one signed policy version against a staging server, including the
  kill-switch path.
- `CG-MOB-VND-001`, `CG-MOB-VND-002`, `CG-MOB-VND-003` (remain
  `external-blocked`): the only pre-license step that moves evidence is
  pinning exact vendor product versions and archived source digests in the
  machine registry
  (`python tools/detection_validation/scripts/competitive_source_registry_gate.py --strict`)
  plus the vendor-specific permitted-use receipt (the `CG-BMK-001-K`
  precursor). No lab work may start before the legal receipt. The
  `verimatrix-xtd` token in `CG-MOB-VND-003` remains the historical tooling
  alias; the current owner label is Guardsquare (acquisition completed
  2026-02-05).
- `CG-MTD-001`, `CG-MTD-001-A`, `CG-MTD-001-B` (`smoke_local ->
  synthetic_parity`): minimal artifact is a versioned posture snapshot plus an
  audited allow/observe/warn/step-up/block decision trace on fixture input.

### Lane B: endpoint EDR (CrowdStrike and SentinelOne comparison lanes; rollback and self-hosted differentiators)

- `CG-EDR-001` (`smoke_local -> synthetic_parity`): single-node replay
  convergence run recorded under `docs/benchmarks/runs/`; existing
  replay-identity precursor:
  `python tools/detection_validation/scripts/event_envelope_replay_probe.py`.
- `CG-EDR-003` (`smoke_local -> governed_lab`, one OS lane at a time): signed
  install/update/rollback matrix for one OS lane first; existing precursors:
  `python tools/detection_validation/scripts/macos_release_artifact_preflight.py`
  and
  `python tools/detection_validation/scripts/generate_release_reliability_gate.py`.
  Owned rollback evidence here is also what keeps the comparison tables
  honest: SentinelOne rollback stays scoped as vendor-declared Windows-only,
  and no generalized-rollback wording is available to any vendor row.
- `CG-EDR-004-A` (`source_review -> smoke_local`): accepted-corpus ledger for
  the hash catalogs already acquired by the ML campaign scripts; existing
  structural precursor:
  `python tools/detection_validation/scripts/governed_fp_fn_corpus_gate.py`.
- `CG-EDR-004-B` (stays `hold`): minimal artifact is the sealed split manifest
  plus a zero-leakage report; the hist256 holdout stays unopened until the
  authorization receipt exists.
- `CG-EDR-004-C` (stays `external-blocked`): minimal artifact is the
  isolated-runner authorization record and runner configuration snapshot
  (no production credentials, controlled egress) before any detonation.
- `CG-EDR-004-D` (stays `hold`): nothing can promote before `CG-EDR-004-B`,
  `CG-EDR-004-C` and the `CG-BMK-001-H/I/J` review chain; no interim artifact
  is defined on purpose.
- `CG-EDR-VND-001`, `CG-EDR-VND-002` (remain `external-blocked`): pre-license
  step mirrors the mobile vendor rows - pinned vendor source/version digests
  in the source registry plus the `CG-BMK-001-K` permitted-use receipt; vendor
  EULA benchmark clauses decide whether a named run is permitted at all.
- `CG-BMK-001-B` (`source_review -> smoke_local`): preregistered clean-cohort
  definition (independent unit, cluster keys, strata) committed before any
  clean run; structural precursor:
  `python tools/detection_validation/scripts/governed_fp_fn_corpus_gate.py`.
- `CG-BMK-001-H`, `CG-BMK-001-I` (`source_review -> smoke_local`): immutable
  preregistration digest and a custody/exclusion ledger template bound to one
  real run bundle; both are prerequisites shared by every named-vendor lane.
- `CG-BMK-001-K` (`source_review -> smoke_local`): one completed
  vendor-specific permitted-use/legal review record (any single vendor)
  establishes the template every other named-vendor row reuses.

### Lane C: self-hosted parity (Elastic and Wazuh reference lanes)

- `CG-SIEM-001` (parent): closes only through `CG-SIEM-001-B/C/D`; no separate
  interim artifact.
- `CG-SIEM-001-B`, `CG-SIEM-001-C` (`smoke_local -> synthetic_parity`): first
  OCSF and ECS fixture pair for one endpoint event class plus its
  semantic-loss ledger; the registry precursor is already green:
  `python tools/interoperability/validate_schema_registry.py --strict`.
- `CG-SIEM-001-D` (`source_review -> smoke_local`): compatibility matrix
  covering upgrade/downgrade, unknown-field and round-trip behavior for the
  first fixture pair above.
- `CG-SIEM-SEL-001`, `CG-SIEM-SEL-002`, `CG-SIEM-DRI-001`: promotion is by
  record, not code - partner qualification packet, scored selection record
  (`>= 75/100`, no veto) and DRI activation receipt, in that order.
- `CG-SIEM-002-E` (stays deferred): the only allowed pre-selection work is
  ECS fixture conformance through `CG-SIEM-001-C`, because Elastic is the
  default candidate, not the selected provider.
- Wazuh-facing parity boundaries are tracked in
  `docs/benchmarks/COMPARATIVE_BENCHMARK_POSITIONING.md`; their executable
  gates already exist and run today:
  `python tools/detection_validation/scripts/validate_external_rule_readiness.py`,
  `python tools/detection_validation/scripts/external_rule_event_contracts.py`
  and
  `python tools/detection_validation/scripts/posture_inventory_compliance_readiness_gate.py`.

### Low-priority TBD items (lane marker only)

These retain their `TBD:` commands unchanged and receive no next-step in this
pass; only their lane is tagged so they cannot be mistaken for unassigned.
- [MTD-integrations] `CG-MOB-VND-004`, `CG-MTD-002`, `CG-MTD-002-A`,
  `CG-MTD-002-B`, `CG-MTD-002-C`.
- [mobile-build-later] `CG-MOB-002-C`, `CG-MOB-002-D`.
- [EDR-vendor-later] `CG-EDR-VND-003`, `CG-EDR-VND-004`.
- [SIEM-other-providers] `CG-SIEM-002`, `CG-SIEM-002-A`, `CG-SIEM-002-B`,
  `CG-SIEM-002-C`, `CG-SIEM-002-D`, `CG-SIEM-002-F`, `CG-SIEM-PILOT-001`,
  `CG-SIEM-ADOPT-001`, `CG-SIEM-EXP-001`, `CG-SIEM-LEG-001` (calendar-bound:
  inventory is immediate and the external `2026-09-14` deadline is already
  recorded above).
- [CNAPP] `CG-CNA-001`, `CG-CNA-001-B`, `CG-CNA-001-C`, `CG-CNA-001-D`,
  `CG-CNA-001-E`, `CG-CNA-SEL-001`, `CG-CNA-DRI-001`, `CG-CNA-PILOT-001`,
  `CG-CNA-ADOPT-001`, `CG-CNA-EXP-001`, `CG-CNA-002`, `CG-CNA-002-A`,
  `CG-CNA-002-B`, `CG-CNA-002-C`.
- [benchmark-measurement] `CG-BMK-001-C`, `CG-BMK-001-D`, `CG-BMK-001-E`,
  `CG-BMK-001-F` (all four are unblocked by the shared physical device lab in
  the dependency graph below), `CG-BMK-001-J`, `CG-BMK-001-L`.
- [adjacent watchlist] all `CW-*` backlog contracts remain `hold` as recorded
  in their own section.

## Gate dependency graph (shared evidence infrastructure)

Added 2026-07-21. Several `external-blocked` items share the same physical or
governance infrastructure; standing up one shared gate unblocks multiple
vendor lanes at once, so spend ordered by this graph is cheaper than treating
each lane independently. Arrows read "unblocks". This graph assigns no owner
and authorizes no run.

- Governed physical Android/iOS device lab (device custody plus
  authorization) -> `CG-MOB-001-B`, `CG-MOB-001-C`, `CG-MOB-VND-001`,
  `CG-MOB-VND-002`, `CG-MOB-VND-003`, `CG-MOB-VND-004`, `CG-MTD-002-A`,
  `CG-MTD-002-B`, `CG-BMK-001-C`, `CG-BMK-001-D`, `CG-BMK-001-E`,
  `CG-BMK-001-F`. One lab serves the Guardsquare, Appdome, Zimperium and
  Lookout lanes; its packets are consumed by
  `sdk/mobile/scripts/physical_attack_lab_evidence.py --strict` and
  `sdk/mobile/scripts/validate_sdk_release_contract.py`.
- Healthy Windows lab host (transport-stable) -> `CG-EDR-003` (Windows lane),
  `CG-EDR-004-C` (isolated detonation runners), `CG-EDR-VND-001` through
  `CG-EDR-VND-004`, plus the pending per-detection latency dimension and the
  Elastic-facing live-evidence wave tracked in
  `docs/benchmarks/COMPARATIVE_BENCHMARK_POSITIONING.md`.
- Benchmark governance chain `CG-BMK-001-H` (preregistration) ->
  `CG-BMK-001-I` (custody) -> `CG-BMK-001-J` (independent review) ->
  `CG-BMK-001-L` (public wording), with `CG-BMK-001-K` (legal permitted-use)
  required per vendor before artifact access: shared by every named mobile
  (`CG-MOB-VND-*`) and EDR (`CG-EDR-VND-*`) protocol. Built once, it
  amortizes across at least eight named-vendor receipts.
- Sealed corpus governance `CG-EDR-004-A` -> `CG-EDR-004-B` -> `CG-EDR-004-D`
  also feeds `CG-BMK-001-B` (FPR) and the benign-corpus gap named in the
  comparative positioning document; one accepted-corpus ledger serves the
  generic holdout and all four EDR vendor protocols.
- Signed ingest and anti-replay (`CG-MOB-003-B`) plus release provenance
  (`CG-MOB-002-E`) -> both the Appdome-facing release-packet wave (F2) and
  the Guardsquare-facing runtime-lab wave (F3) in the positioning document;
  a single signed-ingestion proof advances both vendor lanes.
- Shared connector runtime `CG-SIEM-002-A` -> `CG-SIEM-002-B/C/D/E/F`,
  `CG-CNA-001` (CNAPP pilot lane) and `CG-MTD-002` (provider/UEM adapters):
  one runtime acceptance amortizes across SIEM, CNAPP and MTD integrations.

## Official source registry

These sources establish only comparison dimensions and declared product/schema
behavior. Entries were retrieved on 2026-07-16 or 2026-07-17 as recorded in the
machine registry. Before each governed comparison, pin the
exact vendor product version, contract/API revision and archived source digest;
the live URLs below are not immutable evidence.

| Source ID | Class | Scope used here | Official source |
| --- | --- | --- | --- |
| `SRC-GSQ-DEX-001` | vendor_declared | DexGuard obfuscation, encryption, virtualization and RASP dimensions | [Guardsquare DexGuard](https://www.guardsquare.com/dexguard) |
| `SRC-GSQ-IXG-001` | vendor_declared | iXGuard iOS code-hardening and RASP dimensions | [Guardsquare iXGuard](https://www.guardsquare.com/ixguard) |
| `SRC-GSQ-VIRT-001` | vendor_declared | virtualization mechanism and stated performance trade-offs | [Guardsquare code virtualization](https://www.guardsquare.com/blog/dexguard-introduces-code-virtualization-android) |
| `SRC-GSQ-RASP-001` | vendor_declared | runtime-integrity comparison layers | [Guardsquare RASP and threat monitoring](https://www.guardsquare.com/blog/protecting-runtime-integrity-with-rasp-threat-monitoring) |
| `SRC-ZIM-ZDEF-001` | vendor_declared | zDefend in-app RASP category | [Zimperium zDefend brief](https://lp.zimperium.com/hubfs/MAPS_zDefend/SB/GEN/zDefend_Solution_Brief24.pdf?hsLang=en) |
| `SRC-ZIM-MTD-001` | vendor_declared | device MTD category, distinct from shielding | [Zimperium MTD overview](https://lp.zimperium.com/hubfs/MTD/WP/GEN/Zimperium_Mobile_Threat_Defense.pdf?hsLang=en) |
| `SRC-LOOK-MES-001` | vendor_declared | mobile endpoint app/device/network/phishing posture | [Lookout Mobile Endpoint Security](https://www.lookout.com/platform/mobile-endpoint-security) |
| `SRC-CS-FALCON-001` | vendor_declared | Falcon cross-domain platform comparison dimensions | [CrowdStrike Falcon Platform](https://www.crowdstrike.com/en-us/platform/) |
| `SRC-CS-ENDPOINT-001` | vendor_declared | endpoint prevention, detection, investigation and response dimensions | [CrowdStrike Endpoint Security](https://www.crowdstrike.com/en-us/platform/endpoint-security/) |
| `SRC-S1-XDR-001` | vendor_declared | Singularity endpoint, identity, cloud and third-party XDR dimensions | [SentinelOne Singularity XDR](https://www.sentinelone.com/platform/singularity-xdr-protection/) |
| `SRC-S1-ENDPOINT-001` | vendor_declared | endpoint prevention, Storyline, response and rollback dimensions; platform-specific scope requires separate qualification | [SentinelOne Singularity Endpoint](https://www.sentinelone.com/platform/endpoint-protection-platform/) |
| `SRC-MS-MDE-001` | vendor_declared | Defender for Endpoint prevention, detection, investigation and response dimensions | [Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint) |
| `SRC-MS-XDR-001` | vendor_declared | Defender cross-product endpoint, identity, email and application dimensions | [Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender) |
| `SRC-PAN-XDR-001` | vendor_declared | Cortex endpoint, network and cloud XDR dimensions | [Cortex XDR](https://docs-cortex.paloaltonetworks.com/p/XDR) |
| `SRC-PAN-XQL-001` | vendor_declared | Cortex raw endpoint, network, cloud and third-party query dimensions | [Cortex XQL](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/XQL-language-features) |
| `SRC-APPDOME-SUITE-001` | vendor_declared | Android/iOS RASP, runtime anti-tampering, hooking and app-shielding dimensions | [Appdome Mobile RASP and App Shielding](https://www.appdome.com/mobile-app-security/mobile-rasp-and-app-shielding/) |
| `SRC-APPDOME-OBF-001` | vendor_declared | Android/iOS binary obfuscation and anti-reversing dimensions | [Appdome binary obfuscation](https://www.appdome.com/how-to/mobile-app-security/mobile-code-obfuscation/binary-code-obfuscation-anti-reversing-for-android-ios-apps/) |
| `SRC-VMX-XTD-001` | vendor_declared | current Guardsquare owner page for XTD technology acquired from Verimatrix (acquisition completed 2026-02-05); ID retained as historical compatibility alias | [Guardsquare XTD](https://www.guardsquare.com/xtd) |
| `SRC-GOOG-ING-001` | vendor_declared | current Google SecOps UDM ingestion methods, regional endpoints and limits | [Google SecOps ingestion methods](https://docs.cloud.google.com/chronicle/docs/reference/ingestion-methods) |
| `SRC-GOOG-LEG-001` | vendor_declared | previous-generation UDM/raw ingestion, deduplication and fallback constraints | [Google SecOps previous-generation Ingestion API](https://docs.cloud.google.com/chronicle/docs/reference/ingestion-api) |
| `SRC-GOOG-LIFE-001` | vendor_declared | modern/previous-generation API and ingestion lifecycle comparison | [Google SecOps APIs overview](https://docs.cloud.google.com/chronicle/docs/reference/google-secops-api-libraries-overview) |
| `SRC-MS-LOG-001` | vendor_declared | modern Logs Ingestion API/DCR target | [Azure Monitor Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview) |
| `SRC-MS-MIG-001` | vendor_declared | legacy HTTP Data Collector migration requirements | [Migrate to Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/custom-logs-migrate) |
| `SRC-MS-ASIM-001` | vendor_declared | Sentinel ASIM schema/version/field semantics | [ASIM schemas](https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-schemas) |
| `SRC-EL-ECS-001` | vendor_declared | ECS core/extended mapping semantics | [ECS guidelines](https://www.elastic.co/docs/reference/ecs/ecs-guidelines) |
| `SRC-EL-INT-001` | vendor_declared | Elastic integration build/test/package lifecycle | [Elastic integration developer guide](https://www.elastic.co/docs/extend/integrations) |
| `SRC-OCSF-001` | normative | vendor-neutral schema framework and extensions | [OCSF](https://ocsf.io/) |
| `SRC-ANDROID-PROF-001` | normative | Android CPU, memory, graphics and battery profiling contract | [Android Studio Profiler](https://developer.android.com/studio/profile/) |
| `SRC-ANDROID-POWER-001` | normative | Android ODPM and battery/power instrumentation constraints | [Android Power Profiler](https://developer.android.com/studio/profile/power-profiler) |
| `SRC-APPLE-XCT-001` | normative | repeatable Apple CPU, clock, memory, storage and launch metrics | [XCTest performance tests](https://developer.apple.com/documentation/xctest/performance-tests) |
| `SRC-APPLE-METRICKIT-001` | normative | aggregate Apple on-device power, performance and diagnostics contract | [MetricKit](https://developer.apple.com/documentation/metrickit) |
| `SRC-WIZ-CLOUD-001` | vendor_declared | CSPM, CIEM, DSPM and Security Graph comparison dimensions | [Wiz Cloud](https://www.wiz.io/platform/wiz-cloud) |
| `SRC-WIZ-DSPM-001` | vendor_declared | DSPM and cloud graph comparison dimensions | [Wiz DSPM](https://www.wiz.io/solutions/dspm) |
| `SRC-PRIS-CSPM-001` | vendor_declared | CSPM and graph/attack-path comparison dimensions | [Prisma Cloud CSPM](https://www.paloaltonetworks.com/prisma/cloud/cloud-security-posture-management) |
| `SRC-PRIS-CNAPP-001` | vendor_declared | declared CSPM/CIEM/DSPM CNAPP scope | [Prisma Cloud CNAPP design guide](https://www.paloaltonetworks.com/resources/guides/cloud-native-application-protection-platform-design-guide) |

## Claim boundaries and exit rules

- `vendor_declared` material may define a test dimension, never a result.
- Source review, fixtures, synthetic parity and roadmap completion cannot become
  production, prevention, scale, efficacy, parity, replacement or superiority
  wording.
- A same-app lab run applies only to pinned versions, policies, artifacts,
  devices and scenarios. A failed bypass attempt does not prove unbypassability.
- Public named-vendor comparisons require legal/license review, reproducible
  artifact access, disclosed methodology and `independent_validation`.
- Schema/export success is not SIEM parity; imported CNAPP findings are not
  Tamandua CSPM/CIEM/DSPM scanning; app posture is not full-device MTD.
- Every item exits `mapped`, `active`, `external-blocked`, or `hold` only when the
  owner records immutable source/artifact identity, exact command and result,
  evidence class, denominators, failures, limitations and supersession link.
- Generated authority is refreshed only through its owning tools. No row here
  authorizes implementation, deploy, publication, release or a public claim.
