---
name: secops-risk-metrics-multistage
description: UEBA threat hunting via 30d SecOps metrics DAGs (30-day behavioral baseline, peer cohort comparison, 360° entity health check, CUSUM drift, entity risk score, multi-sector threat fusion, and 30d-baseline MAD on metric-catalog vectors). Raw/custom-window MAD → secops-statistical-hunter.
compatibility: Requires Google SecOps with Risk Analytics and SecOps MCP.
metadata:
  author: Greg Kushmerek
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes multi-sector outlier hunting using 30-day Risk Analytics (`metrics.*`).
Operational execution: `references/turn-execution-lifecycle.md`.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **UEBA / 30-Day Baselines** (`metrics.*`) / **Behavioral Risk** / **Multi-Sector Fusion**: Execute `secops-risk-metrics-multistage`. Unqualified fusion, fleet-prevalence / Patch Tuesday, rare binary/domain, or service-account repository access requests route to `secops-risk-metrics-multistage` when a 30d `metrics.*` vector exists, and to `secops-statistical-hunter` when raw UDM events or custom sub-day windows are named.
* **Jitter & Raw UDM**: Sub-second jitter requires raw logs; emit Skill Handoff Card to `secops-statistical-hunter` and yield turn (0 tools called).
* **Scheduled Exfiltration**: Offer Longitudinal CUSUM Drift (`longitudinal_cusum.yl2`, one ≤14d query; not Mode B) or emit Skill Handoff Card to `secops-statistical-hunter` for sub-day cron cadence.
* **Rollouts & Rare Binaries**: Deploy Fleet Prevalence Normalization with Entity Graph (`rolling_max <= 3`).
* **Non-Metrics Telemetry Steering Mandate** (Git, raw UDM, raw-field MAD): Handoff Card → `secops-statistical-hunter`. Metrics-vector MAD (any mode): `stage2_math_models/mad.yl2`.
* **Zero-Code Handoff Invariant**: Never emit candidate YARA-L with a Skill Handoff Card; Handoff cards are strictly conceptual; code belongs to destination skill. On accepted handoff, release the Active Hunt Session Lock.
* **Bilateral UEBA Harness (Open-Ended Threat / Exploit / CTI Solutions)**: When no single `Active Skill:` test header is present and an analyst asks for a UEBA solution to an exploit, vulnerability, or threat behavior requiring short-window (`by 5m`/`by 1h`) process/network correlations alongside 30d baselines (`references/statistical-hunting-cooperative-framework.md`), never declare UEBA a poor fit because `metrics.*` is bucketed `by 1d`; co-design a Bilateral UEBA Harness pairing `secops-risk-metrics-multistage` (30d `metrics.*` macro deformations) with `secops-statistical-hunter` (bounded-window Markov 2-gram lineage, Shannon entropy, Poisson Fano burst, EWMA velocity, CV jitter, Zipfian rarity — never 30d raw scans over VPC/DNS/HTTP/Auth) and `agentic_ueba` UDM loopback (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`). Keep single-vector jitter, raw-field MAD, and scheduled cron exfiltration prompts on the Zero-Code Handoff Card above.

---

## ⏰ Time Model (Prerequisite for Every Query)
UTC throughout; `metrics.*` are `00:00Z` day buckets. `startTime`/`endTime` pick scored days; the 30d baseline comes from `metrics.*` (anchored at `startTime` day), never a wider window (except `stage2_math_models/mad.yl2` / `templates/pipelines/mad_robust_z_4stage.yl2`, which computes raw daily median/MAD over a 14d–30d search window while `$in_scoring_window` gates root output to the scored day(s)). Mode A: `startTime` = today `T00:00:00Z` (Entity Graph: UTC date −2d at `T00:00:00Z`; not now−48h, shifting the graph-joined Mode A `metrics.*` baseline to `[D−32, D−2)`), `endTime` = now; never rolling. Other skills' mode windows do not apply.

## ⏱️ Evaluation Modes

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: today `00:00Z`→now vs 30d baseline (`window: 30d`; disclose elapsed UTC day fraction on the Pre-Flight Card and Pillar 1 since comparing a partial UTC day against a full-day `period: 1d` mean biases sub-full-day $Z$ low, or score the last complete UTC day on request). Target dates (e.g. "Aug 12") auto-bypass Mode B.
2. **Mode B: Fixed-Baseline Timeline (`TIMELINE_BREAKDOWN`)**: 2–7 days, one query (`match: $entity by 1d`), start ≤1y ago.
3. **Mode C: Per-Day Baseline Timeline** (`run_command` present only): one query per UTC day, each vs its own trailing 30d, collated by `scripts/timeline_assembler.py`.
* **Window Invariant**: The platform anchors ONE `period: 1d, window: 30d` baseline at start day; all scored days reuse it. Mode B: state baseline dates. No `run_command`: no Mode C; per-day baselines and >7d need a client that runs local scripts. Details: `references/timeline-modes-guide.md`.

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE

### 🚦 State 1: Pre-Flight Clearance & Specification (Zero Execution on Turn 1) (MANDATORY STEP 1: PRE-FLIGHT CLEARANCE)
Every pre-flight turn (Turn 1, incl. *"Run..."*/*"Scan..."*, and any State 3 pivot): probe, preview, offer modes; no execution. Execution and 5-pillar findings follow clearance.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B is **ONLY UNLOCKED** when **BOTH** are explicitly defined:
1. **Entity Scope** (user, cohort, fleet / cloud) **AND**
2. **Telemetry Vector(s)** (selected from canonical sectors: Cloud CRUD, Workspace, Network Egress, DNS Resolution, Web & Proxy, Endpoint, Auth, Security & EDR Alerts (`alert_event_name_count`), or 360° Discovery Sweep).

> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> When telemetry vector is unspecified, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. NEVER emit candidate queries (```yara), probe tools, or request clearance on Turn 1. Consult `references/consultative-worksheet.md` (`### Threat Hypothesis` & `### Summary View`) and yield turn (0 tools called), asking: *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"* On vector selection, enter Phase 1B in that same turn.
> *(Expert Bypass: When Scope + Vector are specified upfront, proceed directly to Phase 1B, resolving identity first; never bypass the Turn 1 Clearance Gate).*

### 🕸️ 360° Entity Behavioral Risk Radar & Multi-Sector Threat Fusion
* **360° Radar (360° 7-Shard Architecture)**: 6-sector health check (`references/360-behavioral-radar-guide.md`) via decoupled micro-queries (`templates/pipelines/radar_360_decoupled_sector.yl2`, plus alert/web shards); all 6 sectors must be reported (user: Auth, Cloud, Workspace, Network, DNS, Web; host: Security & EDR Alerts in the Cloud slot, Endpoint in Workspace). Radial radar for individuals; Ranked Outlier Bars or Heatmap Matrix for fleet sweeps.
* **Multi-Sector Fusion & Hybrid Pipelines**: fusion ($D = \sqrt{\sum \max(0, Z_i)^2}$, $D^2 = \sum \max(0, Z_i)^2$), roll-up (`rollup_sector_fusion_4stage.yl2`), triad (`part_of_the_whole_triad_multilevel.yl2`) and rare-destination templates, slots, pairing rules: `references/metric-sector-catalog.md`; max 2 event stages per query. Hybrid: `hybrid_metric_*.yl2` (`scripts/ueba_hybrid_engine.py`, `match: $entity by 1d`; Patch Tuesday: `hybrid_metric_fleet_prevalence_2stage.yl2`).
* **Cloud Telemetry**: For service account cloud repository access (`resource_read_*`, `_written_*`, `_creation_*`, `_deletion_*`), baseline all 4 CRUD families and origin IP (`templates/pipelines/cloud_repository_scope_dual_branch.yl2`, `<field>: <field>`; apply SA regex only when scoped to service accounts, or use standalone `resource_*` extractors for general user CRUD).

### 🎯 CTI & Threat Report Mapping
**Map to UEBA Metric Tables** (`metrics.*`, `references/consultative/mitre-attack-killchain.md`). When an open-ended CTI/exploit inquiry also requires minute/hour windowed correlations (process parent$\to$child transitions, CLI/URL entropy, sub-hour bursts), pair `metrics.*` macro pipelines with `secops-statistical-hunter` bounded-window statistical pipelines and `agentic_ueba` loopback (`references/statistical-hunting-cooperative-framework.md`) rather than falling back to static point-in-time filters. **Transition Directly to Phase 1B**: probe, Pre-Flight Card & Literal Query Preview, clearance question.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (expert prompt, Phase 1A selection, or CTI mapping; card precedes query preview):
1. **Turn 1 Tool Invariant** (every pre-flight turn, incl. State 3 pivots): Limit tools to identity spot-checks (incl. AD TEAM LOOKUP, run first) and one probe (`udm_search`, `maxEvents: 1`) of the event filter alone (no `stage`, `match:`, `metrics.`). Never probe the candidate itself, even with `maxEvents: 1`; it runs only after clearance (the Turn-1 probe validates the event filter only; multi-stage grammar is validated on the cleared Turn-2 run). An empty `{}` response from the 10m probe is a valid 200 OK compile check — NEVER re-probe with wider windows or alternate host filters when a probe returns `{}` (at most 1 probe on Turn 1 unless a syntax error is returned). After the probe, call 0 more tools; emit card, preview, and clearance question, then yield.
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs*: Display names (with spaces) are NOT `user.userid`. First names (`Frank`) or user emails (`u@d` → local `user.userid` like `admin`) need a target-window/14d spot-check; `@*.iam.gserviceaccount.com`, host, fleet skip it.
   - *14-Day UDM Spot-Check* (or target window): `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase or target.user.email_addresses = "<name>" nocase or principal.user.email_addresses = "<name>" nocase or target.user.user_display_name = /.*<name>.*/ nocase or principal.user.user_display_name = /.*<name>.*/ nocase', startTime: "<ISO_14D_AGO>", endTime: "<ISO_NOW>", maxEvents: 5)`.
   - *Match Found ($\ge 1$ events)*: Extract verified technical `user.userid` from `target.user.userid` or `principal.user.userid`. Echo in card: `• Target Entity / Scope: <Name> (Verified User ID: <id>)`.
   - *HARD RESOLUTION GATE (ZERO GUESSING & NO SPEC CARD)*: If 0 events match an unqualified name (no `.`/`@`), **NEVER GUESS A USERNAME AND NEVER EMIT PRE-FLIGHT CARD**. **HALT IMMEDIATELY (0 additional tools called)**, asking: *"I could not resolve an active technical `user.userid` for '<Name>' in recent UDM telemetry. What is their corporate email or technical username?"* (0 default-window hits on `a.b`/`u@d` keeps input.)
3. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   Emit Pre-Flight card before candidate query:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope: [Target User/Host ID or Fleet]
   • Threat Hypothesis: [Operational hypothesis summary]
   • Baseline Horizon Spine: 30-Day (period: 1d, 30d; graph-joined Mode A: [D-32, D-2))
   • Peer Cohort & Roster: [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode: [chosen mode: A today (+ elapsed UTC fraction) | B 2–7d + baseline dates | C per-day if run_command]
   • Statistical Model: [Model & Template, e.g. CUSUM (`longitudinal_cusum.yl2`)]
   • Significance Threshold: [Gate, §2.1: Z >= 3.0σ | >= 2.0× | D >= 3.5σ (multi-sector Euclidean distance D >= 3.5, D^2 >= 12.25)]
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)* & *Tool-Precondition Code Block Embargo*: Probe once with ISO 8601 UTC timestamps: `udm_search(query="<single_event_udm_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. Relative 'now-10m' is invalid. Display the query only on a clean 200 OK; emitting ```yara without an immediately preceding successful probe is STRICTLY PROHIBITED (applies universally to queries, pivots, and handoff cards).
   * *Peer Cohort & Roster*: List cohort entities; if $N < 7$, flag `⚠️ Sparse Baseline Caution (N < 7)`. Peer Cohort Roster Requirement: no peers mentioned → fleet only; peers mentioned but unnamed → AD TEAM LOOKUP (multi-stage-metrics-guide.md), else ask for the roster; never drop. Use the guide's aggregated query (`match: $dept`); raw filters return no fields. No members → ask, never infer.
   * *Interactive Entity Graph Dimension Mandate*: Express joins under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Model Concordance*: Match outcome/condition/order to templates; card threshold = root `condition:` (`references/model-concordance-guide.md` §2.1).
   * *Two-Phase Chained Hunt Specification* (cross-entity): Phase 1 (UEBA Outlier executed via `udm_search`), Bridge Contract ($host, $timestamp, $user, $caller_ip), Phase 2 (Cloud UDM Query / Data Table Bridge via `templates/pipelines/hybrid_data_table_bridge_2stage.yl2` — always explicitly write the literal `%ueba_hunt_bridge.entity`, e.g., `principal.asset.hostname in %ueba_hunt_bridge.entity` or `principal.user.userid in %ueba_hunt_bridge.entity`, in the Turn 1 Phase 2 preview and Turn 2 Pillar 4; never call `create_data_table` or `add_rows_to_data_table` in Turn 1/2; materialize only in State 3 upon explicit analyst approval).
4. **Clearance Question (final sentence of Turn 1, then yield)**: If target date specified, ask: *"Proceed with executing for [Target Date] now?"*. Otherwise ask: *"Would you like me to proceed with **Mode A (Today vs 30-Day Baseline)** or **Mode B (2–7 Day Fixed-Baseline Timeline)**[, **Mode C (Per-Day Baseline)** if `run_command`]? (Thresholds can be tuned first.)"*.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 5-Pillar Report (After Clearance) (MANDATORY STEP 2: PRESENT FULL 5-SECTION REPORT)

1. **State 2 Entry Condition**: If the preceding turn displayed a PRE-FLIGHT HUNTING SPECIFICATION card and the candidate query, its event filter probed clean (200 OK), Mode A/B clearance means execute now (Mode C / "Clearance granted" / "Run it" too). Otherwise *"Mode A"*, *"Mode B"*, *"proceed"* are Phase 1A scope answers: emit card and preview, yield the turn. A follow-up pick (`[1]`/`[2]`/`[3]`) is never clearance.
2. **Execution Telemetry Retrieval Mandate**: Analyst clearance authorizes immediate query execution: always dispatch approved multi-stage `metrics.*` query via `udm_search` (for 360 Radar, dispatch all 6 sector queries returning `"stats"` in a single parallel batch and synthesize the unified 5-Pillar report directly without calling `render_forensic_dossier` 6 separate times) before generating text or rendering report, regardless of preliminary spot-check counts. Raw event filter substitutions are invalid on execution turns.
3. **Deterministic 5-Pillar Forensic Triage Report Structure** (omit a separate query pillar; the verbatim executed multi-stage query is placed inside Pillar 5 as the ONLY ```yara block in Turn 2):
#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) — Executive Summary & Calibrated Risk Index (CRI) (`window: 30d`). Single visual surface: `<agent-embed src="file:///<artifact_dir>/<chart>.html"></agent-embed>` (registered via `write_file`) in Jetski (`run_command` present); `<svg>` in MCP/webview; Client Tool (if present); ASCII on request. Zero data-uri or raw SVG in chat Markdown. Unicode magnitude bars (`▰▰▰▰▱▱▱▱`). `references/chart-specifications-guide.md`.
#### 2. Ranked Outlier Summary & Provenance Stamp: Columns: `Entity`, `Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`. (Mode C adds a shard date table.) Stamp execution provenance (returned row count, evaluation mode, requested startTime/endTime window, projected schema columns, and client wall-clock dispatch time if measured; never fabricate events scanned).
#### 3. Forensic Vector Breakdown: Threat translation, scenarios, SOC playbook, **Agentic Next Steps**: three follow-ups `[1]`/`[2]`/`[3]` fitted to outcome (`ACUTE_OUTLIER`, `CLEAN_OR_SUBTHRESHOLD`, `FLEET_WAVE`, `SPARSE_BASELINE`; `triage_formatter.py`).
#### 4. Chronicle UI Manual Pivot (Triage Reference Only): Passive UDM filter in a ```text fence for Chronicle UI (**Case Sensitivity On** when running `metrics.*` in UI; never emit ```yara in Pillar 4).
#### 5. Collapsible Technical Appendix (Statistical & Mathematical Appendix): ($N=30d$), piecewise CRI (`CRI(Z) = 0 for Z <= 0`, `round(100 / (1 + exp(-0.6 * (Z - 3.0))))` for $Z > 0$), $D = \sqrt{\sum \max(0, Z_i)^2}$ (`references/calibrated-risk-index-guide.md`), and the verbatim executed multi-stage query as the ONLY ```yara block in Turn 2.
4. **Zero-Telemetry Clean Hunt Exemption (True Negative Audit Summary)**: When executed query returns empty `stats` (`{}` or `{"stats": []}`), emit Clean Hunt Audit (+ Agentic Next Steps):
   - `#### 1. Statistical Outlier Report: [Target Metric] (Nominal Baseline)`: 0 observed events / 0 ranked outliers ($Z = 0.00\sigma, D = 0.00, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline**; no `🚨`) + `[1]`/`[2]`/`[3]` pivots (no `5-spoke`/`6-spoke`/`spider radar` in fleet text).
   - Always include all 5 numbered pillars (`#### 1. Statistical Outlier Report` through `#### 5. Collapsible Technical Appendix`, including `#### 2. Ranked Outlier Summary & Provenance Stamp`, `#### 3. Forensic Vector Breakdown`, `#### 4. Chronicle UI Manual Pivot`, and the executed ```yara query in `#### 5.`) populated with nominal baseline values (for 360°/fleet 360°, also report all 6 sectors and $D$).

### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock & Boundary)
* **State 3 → Phase 1B Agentic Pivot Loop**: Selecting a follow-up (`[1]`/`[2]`/`[3]`) re-enters Phase 1B carrying forward entity ID, cohort, and bridge keys (`$host`, `$user`, `$caller_ip`) without re-asking Phase 1A.
* **Entity Shift**: On *"same query for"*, retain Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT) and Re-enter State 1 for new entity.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Hunt Tool Contract**: Active hunts in Turn 1 and Turn 2 run on `udm_search` alone — probe, then execute the approved query (360° Radar: 6 sector queries / 7-shard architecture; two-phase bridge: Phase 1 then Phase 2; Mode C: once per day shard). Never call `create_data_table` or `add_rows_to_data_table` in Turn 1 or Turn 2; data-table materialization (`%ueba_hunt_bridge`) and Clean Hand-Off (`create_case_comment`/`import_events`) are invoked only in State 3 upon explicit analyst approval after previewing rows and table name. Case, alert, rule, and playbook state belong to other skills.
* **THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)**:
  1. **Zero Data Simulation (NEVER Fabricate Data)** / **Zero Generative Simulation & Strict Data Grounding Contract**: Every score, count, and timestamp MUST come from executed tool output; baselines ($\mu, \sigma$) and $Z, \text{CRI}$ come from 30-day baseline model. Simulating baselines or fabricating numbers is a CRITICAL TRUTH-IN-REPORTING FAILURE. (Truth Over Completion: 0 events is a valid hunt.)
  2. **Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)**: Never invent UDM fields or uncompiled YARA-L grammar.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If API query fails, STOP IMMEDIATELY; no simulation. Mode C: report a shard that fails a retry; never fill it.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Active threat hunting enforces Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION). Local arithmetic simulation is a CRITICAL COMPLIANCE VIOLATION. Never run `run_command` for ad-hoc validation, shell searches (`ls`, `grep`, `find`), or math simulation. In Jetski (`run_command` present), run only repository helpers (`scripts/ueba_hybrid_engine.py`, `scripts/radar_collector.py`, `scripts/chart_generator.py`, `scripts/triage_formatter.py`, Mode C collator `scripts/timeline_assembler.py`, and clearance-gated `scripts/chronicle_ingest.py`).
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. 100% self-contained.
* **Native SecOps Architecture**: `metrics.*` UEBA is native to SecOps, leveraging core Google infrastructure. Never claim BQ powers/stores `metrics.*` (BQ is only a monitored cloud target); if asked about BQ, state: BigQuery contributes nothing to SecOps UEBA.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Formulate and execute a single atomic YARA-L query; fracturing into piecemeal searches is STRICTLY PROHIBITED. 360° Radar queries 6 sectors in parallel; a two-phase bridge runs Phase 1 then Phase 2. Mode C reruns the one approved query per day, unchanged (except per-day date pins/windows for graph-joined queries).
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: Scoping probes run before analysis; queries after carry `match:`/`outcome:`. Queries returning `"events"` without `"stats"` trigger `RAW_LOG_DUMP_DETECTED` — abort reporting and present auto-corrected queries (`templates/pipelines/`).

### 2. Compiler & Architectural Invariants
* **Template-First Routing Mandate**: Queries MUST assemble from templates in `~/.gemini/config/skills/secops-risk-metrics-multistage/templates/` (`templates/pipelines/`, or `scripts/ueba_hybrid_engine.py` / `compile_hunt_pipeline`). Select the template yourself using the routing table in `references/multi-stage-metrics-guide.md` §18 & §27.A.
* **Zero-Hallucination Compiler Grammar Contract**: Match blocks accept ONLY bound `$placeholder` identifiers (`$host by 1d`, `$user by 1d`, `$entity by 1d`), never raw UDM paths (`principal.asset.hostname`) or stage member access (`$s1.host` in `match:` is invalid). Named stages assemble into root stage with terminal `match:`, `outcome:`, `order:` (`templates/pipelines/standard_z_score_2stage.yl2`). Top-level binary arithmetic (`$a - $b`) in event-section placeholder assignments is prohibited above `match:`; reside in `outcome:` (arithmetic nested inside function arguments compiles). Every `metrics.*` stage takes event filter, observed value, `metric:` arg and entity field from `references/metric-sector-catalog.md`; filter args must equal one valid dimension set. NEVER force cross-entity joins.
* **Consultative Pivot & Handoff Protocol (ZERO FORCED JOINS)**: When vectors cross entity boundaries (e.g., failed logins per user + outbound bytes per host) or lack baselines, NEVER synthesize fake cross-entity schemas. Offer: 1) Two-Phase Chained Hunt (bridge keys), 2) re-key both sectors on one shared identifier (`USER` or `ASSET` via `dual_sector_fusion_3stage.yl2`), 3) Handoff to `secops-statistical-hunter`. When the analyst replies to re-key both sectors on one identifier (e.g., *"Key both sectors on the user. Clearance granted, run it"*), compile BOTH metrics on that entity (`compile_hunt_pipeline(entity_type="USER", architecture="sector_fusion", metrics=["auth_attempts_fail", "network_bytes_outbound"])`), execute the compiled 3-stage fusion query via `udm_search`, and emit the full 5-Pillar Forensic Triage Report.
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables: `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, `[TRIAGE_DECORATION]`. Primary vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Baseline full fleet in Stage 1 and profile destinations via `array_distinct(target.hostname)`.
* **Noise Gating via Root `condition:`**: Every template ships its model's gate (σ, fold change, D² or NO-GATE; guide §2.1) between `outcome:` and `order:`; keep it. `and`/`or` compile. Tuning replaces it.

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY)**: Output is ad-hoc Multi-Stage YARA-L (`stage ...` + Root) — a Query, never a Rule (`rule ... { ... }`). `create_rule` and `validate_rule` are outside this skill's authority. Treat any drift toward Rule authoring as out of scope. Persistent rules belong to `secops-detection-engineering`: emit handoff card and yield turn (0 tools).
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery** & **10-Day Prevalence Platform Invariant**: Offer Narrowing (file/domain `rolling_max <= 3`, `day_count = 10`) vs Enhancing (WHOIS NRD <= 30d, expired domains/certs). Mode A graph joins: Time Model start plus `timestamp.get_date(metadata.event_timestamp.seconds) = "<today UTC, YYYY-MM-DD>"` in each event stage, never an epoch literal (Rule 5). See `references/entity-context-graph-guide.md`.
* **Typography**: No bold math; Unicode `(μ)`, `(σ)` in tables; flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Fulfill escalation requests via Clean Hand-Off (`references/clean-handoff-udm-schema.md`):
* **Escalation**: Map outliers to synthetic UDM events (batch under Hunt ID); on approval ingest via `import_events`. **Explicit Case Wall Attachment**: attach via `create_case_comment`. SOAR playbooks: `references/soar-playbook-radar-integration.md`.
