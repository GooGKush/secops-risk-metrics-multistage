---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
description: UEBA threat hunting via 30d SecOps metrics DAGs.
compatibility: Requires Google SecOps with Risk Analytics and SecOps MCP.
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes multi-sector outlier hunting using 30-day Risk Analytics (`metrics.*`).
Operational execution: `references/turn-execution-lifecycle.md`.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **UEBA / 30-Day Baselines** (`metrics.*`) / **Behavioral Risk** / **Multi-Sector Fusion**: Execute `secops-risk-metrics-multistage`.
* **Jitter & Raw UDM**: Sub-second jitter requires raw logs; emit Skill Handoff Card to `secops-statistical-hunter` and yield turn (0 tools called).
* **Scheduled Exfiltration**: Offer Mode B Longitudinal CUSUM Drift (`longitudinal_cusum.yl2`) or emit Skill Handoff Card to `secops-statistical-hunter` for sub-day cron cadence.
* **Rollouts & Rare Binaries**: Deploy Fleet Prevalence Normalization with Entity Graph (`rolling_max <= 3`).
* **Non-Metrics Telemetry Steering Mandate** (Git, raw UDM, raw-field MAD): Handoff Card → `secops-statistical-hunter`. Metrics-vector MAD (any mode): `stage2_math_models/mad.yl2`.
* **Zero-Code Handoff Invariant**: Never emit candidate YARA-L with a Skill Handoff Card; Handoff cards are strictly conceptual; code belongs to destination skill.

---

## ⏱️ Evaluation Modes

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: today `00:00Z`→now vs 30d baseline (`window: 30d`); rolling `now-24h` straddles two daily buckets. Target dates (e.g. "Aug 12") auto-bypass Mode B.
2. **Mode B: Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**: 2–14 day horizon (`match: $entity by 1d`), any start date in the last year.
* **Window Invariant**: Each day scored is compared to its own trailing 30d baseline (`period: 1d, window: 30d`). The search window sets how many days are scored (1–14 max), never the baseline. Over 14d: say so, offer today vs 30d or a 14d timeline.

---

## 💡 How Risk Metrics Multi-Stage Analytics Work
3-step **Execution Framework Summary**: 1. **30d Baselines** (`metrics.*`), 2. **Multi-Stage DAGs**, 3. **Statistical Framework** ($Z$, MAD, Poisson, $\Delta Z$, CUSUM, MACD, Circadian, $D$). Ask for more information. Details: `references/multi-stage-metrics-guide.md`.

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE
Lifecycle mechanics and turn contracts are in `references/turn-execution-lifecycle.md`.

### 🚦 State 1: Pre-Flight Clearance & Specification (Zero Execution on Turn 1) (MANDATORY STEP 1: PRE-FLIGHT CLEARANCE)
On Turn 1 (including *"Run..."* or *"Scan..."*), focus strictly on pre-flight alignment: probe the event filter once, render candidate preview, and offer Mode A or Mode B. Multi-stage execution and 6-pillar findings occur strictly in Turn 2 after clearance.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B is **ONLY UNLOCKED** when **BOTH** are explicitly defined:
1. **Entity Scope** (user, cohort, fleet / cloud) **AND**
2. **Telemetry Vector(s)** (selected from canonical sectors: Cloud CRUD, Workspace, Network Egress, DNS Resolution, Web & Proxy, Endpoint, Auth).

> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> When telemetry vector is unspecified, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. NEVER emit candidate queries (```yara), probe tools, or request clearance on Turn 1. Consult `references/consultative-worksheet.md` and yield turn (0 tools called), asking: *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"* Upon analyst vector selection on Turn 2, enter Phase 1B immediately in that same turn: probe the selected vector via `udm_search` (maxEvents: 1), emit formal `PRE-FLIGHT HUNTING SPECIFICATION` card preceding candidate query preview, concluding with the Mode A vs Mode B clearance question.
> *(Expert / Defined Vector Bypass: When both Entity Scope and Telemetry Vector are specified upfront, e.g. "Can you check Frank's authentication activity for anomalies?" or "Run CUSUM on Frank's DNS", proceed directly to Phase 1B, resolving identity and formulating pre-flight card. The Expert Exemption permits bypassing Phase 1A questioning, never the Turn 1 Clearance Gate).*

### 🕸️ 360° Entity Behavioral Risk Radar & Multi-Sector Threat Fusion
* **360° Radar**: 6-sector health check (`references/360-behavioral-radar-guide.md`) via decoupled micro-queries (`templates/pipelines/radar_360_decoupled_sector.yl2`) across all 6 canonical sectors (Auth, Cloud, Workspace, Network, DNS, Web; all 6 must be reported). 6-spoke radial radar for individuals; Ranked Outlier Bars or Heatmap Matrix (Mode B) for fleet sweeps.
* **Multi-Sector Fusion & Hybrid Pipelines**: 2 same-identifier sectors ($D^2 = \sum Z_i^2$): `dual_sector_fusion_3stage.yl2` / `multi_sector_fusion_4stage.yl2`; composite-only (process/resource/alert): `rollup_sector_fusion_4stage.yl2`; triads: `part_of_the_whole_triad_multilevel.yl2`; rare destinations: `rare_destination_ecg_3stage.yl2` / `fusion_rare_destination_3stage.yl2`; max 2 event stages per query; slots/pairing rules/template choice: `references/metric-sector-catalog.md`. Hybrid: `hybrid_metric_*.yl2` (Patch Tuesday: `hybrid_metric_fleet_prevalence_2stage.yl2`).
* **Native Reporting**: Webview/MCP/agentapi: inline `<svg>` in Pillar 1; Jetski: `<agent-embed>`.
* **Cloud Telemetry**: For service account cloud repository access or dormant SA awakening (`resource_read_*`, `resource_written_*`, `resource_creation_*`, `resource_deletion_*`), baseline all 4 CRUD families and origin IP via `templates/pipelines/cloud_repository_scope_dual_branch.yl2` (pass `<field>: <field>` in all `metrics.*` calls so SecOps UI **Case Sensitivity Off** never zeroes baselines).

### 🎯 CTI & Threat Report Mapping
**Map to UEBA Metric Tables**: Map to tables (`metrics.*`). **Transition Directly to Phase 1B**: Emit Pre-Flight Card & Literal Query Preview. **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (expert prompt, Phase 1A vector selection, or CTI mapping; card always precedes the query preview):
1. **Turn 1 Tool Invariant**: Limit Turn 1 tools strictly to identity spot-checks (incl. AD TEAM LOOKUP, run first) and one probe (`udm_search`, `maxEvents: 1`) of the event filter alone (no `stage`, `match:`, `metrics.`). Never probe the candidate itself, even with `maxEvents: 1`; it runs only after Turn 2 clearance. After probe succeeds, call 0 more tools on Turn 1; emit card, query preview, and clearance question in text, then yield. Read templates at `templates/pipelines/<name>.yl2` directly; no exploratory shell searches.
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs*: Display names (with spaces) are NOT `user.userid`. Single unqualified first names (e.g. `Frank`) must be spot-checked in UDM. Hostnames and fleet-wide scopes proceed directly with pre-flight vector formulation.
   - *14-Day UDM Spot-Check*: `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase or target.user.user_display_name = /.*<name>.*/ nocase or principal.user.user_display_name = /.*<name>.*/ nocase', startTime: "<ISO_14D_AGO>", endTime: "<ISO_NOW>", maxEvents: 5)`.
   - *Match Found ($\ge 1$ events)*: Extract verified technical `user.userid` from `target.user.userid` or `principal.user.userid`. In card: `• Target Entity / Scope: <Name> (Verified User ID: <id>)`.
   - *HARD RESOLUTION GATE (ZERO GUESSING & NO SPEC CARD)*: If 0 events match, **NEVER GUESS A USERNAME AND NEVER EMIT PRE-FLIGHT CARD**. **HALT IMMEDIATELY (0 tools called)**, asking: *"I could not resolve an active technical `user.userid` for '<Name>' in recent UDM telemetry. What is their corporate email or technical username?"*
4. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   Before displaying candidate query, emit formal Pre-Flight card:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope:  [Target User/Host ID or Fleet]
   • Threat Hypothesis:      [Operational hypothesis summary]
   • Baseline Horizon Spine: 30-Day (period: 1d, 30d)
   • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode:[Mode A: today OR Mode B: 2–14d]
   • Statistical Model:      [Model & Template, e.g. CUSUM Drift (`longitudinal_cusum.yl2`)]
   • Significance Threshold: [Z >= 3.0σ | 2.0σ <= Z < 3.0σ | D >= 3.5σ]
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)* & *Tool-Precondition Code Block Embargo*: Probe once with ISO 8601 UTC timestamps: `udm_search(query="<single_event_udm_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. Relative 'now-10m' is invalid. Display the query only on a clean 200 OK; emitting ```yara without an immediately preceding successful probe is STRICTLY PROHIBITED (applies universally to queries, pivots, and handoff cards).
   * *Peer Cohort & Roster*: List cohort entities; if $N < 7$, flag `⚠️ Sparse Baseline Caution (N < 7)`. Peer Cohort Roster Requirement: no peers mentioned → fleet only; peers mentioned but unnamed → AD TEAM LOOKUP (multi-stage-metrics-guide.md), else ask for the roster; never drop.
   * *Interactive Entity Graph Dimension Mandate*: Express joins under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Model Concordance*: Match outcome/order clauses to templates (`references/model-concordance-guide.md`).
   * *Two-Phase Chained Hunt Specification*: Cross-entity hunts emit Two-Phase Chained Hunt Specification: Phase 1 (UEBA Outlier), Bridge Contract ($host, $timestamp, $user, $caller_ip), Phase 2 (Targeted Cloud UDM Query).
5. **Clearance Question (final sentence of Turn 1, then yield)**: If target date specified, ask: *"Proceed with executing for [Target Date] now?"*. Otherwise ask: *"Would you like me to proceed with **Mode A (Today vs 30-Day Baseline)** or **Mode B (2–14 Day Timeline)**? (Adjust noise level/significance threshold before execution if desired.)"*.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 6-Pillar Report (After Clearance) (MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT)

1. **State 2 Entry Condition**: If the preceding turn displayed a PRE-FLIGHT HUNTING SPECIFICATION card and the candidate query, its event filter probed clean (200 OK), Mode A/B clearance means execute now. Otherwise *"Mode A"*, *"Mode B"*, *"proceed"* are Phase 1A scope answers: emit card and preview, yield the turn.
2. **Execution Telemetry Retrieval Mandate**: Analyst clearance on Turn 2 authorizes immediate query execution: always dispatch approved multi-stage `metrics.*` query via `udm_search` (for 360 Radar, dispatch sector queries returning `"stats"`) before generating text or rendering report, regardless of preliminary spot-check counts. When telemetry yields zero events or an empty stats payload, report findings affirmatively as nominal baseline under the Clean Hunt Exemption. Raw event filter substitutions are invalid on execution turns.
3. **Deterministic 6-Pillar Report Structure**:
#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) (`window: 30d`). Single visual surface: <agent-embed> in Jetski (`run_command` present); <svg> in MCP/webview; Client Tool (if present); ASCII on request. Zero data-uri or raw SVG in chat Markdown. Unicode magnitude bars (`▰▰▰▰▱▱▱▱`). Details: `references/chart-specifications-guide.md`.
#### 2. Executed Multi-Stage YARA-L Query: Verbatim mirror approved Turn 1 candidate query block. For 360 Radar, display executed sector micro-queries (representative `stage auth_risk` with `order: $z desc`). A bare raw-event filter with no `stage`/`match`/`outcome` is PROHIBITED in Pillar 2.
#### 3. Ranked Outlier Summary & Provenance Stamp: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`. Stamp execution provenance (events scanned, query execution time, projected schema columns).
#### 4. Forensic Vector Breakdown: Threat translation, scenarios, SOC playbook.
#### 5. Chronicle UI Manual Pivot (Triage Reference Only): Passive UDM filter for Chronicle UI (note: enable **Case Sensitivity On** when running `metrics.*` in UI).
#### 6. Collapsible Technical Appendix (Statistical & Mathematical Appendix): ($N=30d$), CRI, $D = \sqrt{\sum \max(0, Z_i)^2}$ (`references/calibrated-risk-index-guide.md`).
4. **Zero-Telemetry Clean Hunt Exemption (True Negative Audit Summary)**: When executed query returns empty `stats` (`{}` or `{"stats": []}`), emit 2-Section Clean Hunt Audit:
   - `#### 1. Statistical Outlier Report: [Target Metric] (Nominal Baseline)`: 0 observed events ($Z = 0.00\sigma, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline**).
   - `#### 2. Executed Multi-Stage YARA-L Query`: Literal query and scope.
   - Pillars 3–6 are waived (360° radar: all 6 sectors plus visual radar).
   - Mode A: say the window was today so far and offer Mode B.

### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock & Boundary)
* **Entity Shift**: On *"same query for"*, retain Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT) and Re-enter State 1 for new entity.
* **Federated Bridge**: When micro-math requested, emit Skill Handoff Card to `secops-statistical-hunter`.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Hunt Tool Contract**: Active hunts run on `udm_search` alone — once to probe, once to execute; Clean Hand-Off adds `create_case_comment`/`import_events` on request. Case, alert, rule, and playbook state belong to other skills.
* **THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)**:
  1. **Zero Data Simulation (NEVER Fabricate Data)** / **Zero Generative Simulation & Strict Data Grounding Contract**: Every score, count, and timestamp MUST come from executed tool output; baselines ($\mu, \sigma$) and $Z, \text{CRI}$ come from 30-day baseline model. Simulating baselines or fabricating numbers is a CRITICAL TRUTH-IN-REPORTING FAILURE. (Truth Over Completion: 0 events is a valid hunt.)
  2. **Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)**: Never invent UDM fields or uncompiled YARA-L grammar. Verified via compiler probe (`<ISO_10M_AGO>` to `<ISO_NOW>`).
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If API query fails, STOP IMMEDIATELY. Zero simulation. STRICTLY PROHIBITED.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Active threat hunting enforces Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION). Local arithmetic simulation is a CRITICAL COMPLIANCE VIOLATION. Never invoke `run_command` for ad-hoc validation, shell searches (`ls`, `grep`, `find`), or local math simulations. In Jetski (`run_command` present), execution is permitted solely on repository helpers (`scripts/radar_collector.py`, `scripts/chart_generator.py`, `scripts/triage_formatter.py`, and clearance-gated `scripts/chronicle_ingest.py`). All baselines and risk derivations remain strictly native to Google SecOps.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. 100% self-contained.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Formulate single atomic YARA-L query for Pillar 2; fracturing into piecemeal searches is STRICTLY PROHIBITED. 360° Radar queries 6 sectors in parallel.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Pillar 2 must contain the literal multi-stage YARA-L block from pre-flight preview; 360 Radar mirrors representative sector query.
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: Scoping probes run before analysis; queries after carry `match:`/`outcome:`. Queries returning `"events"` without `"stats"` trigger `RAW_LOG_DUMP_DETECTED` — abort reporting and present auto-corrected queries (`templates/pipelines/`).

### 2. Compiler & Architectural Invariants
* **Template-First Routing Mandate**: Queries MUST assemble from templates in `templates/pipelines/`. Select the template yourself using the routing table in `references/multi-stage-metrics-guide.md` §27.A.
* **Zero-Hallucination Compiler Grammar Contract**: Match blocks accept ONLY simple bound identifiers (`$host by 1d`, `$user by 1d`), never stage member access (`$s1.host` in `match:` is invalid). Named stages assemble into root stage with terminal `match:`, `outcome:`, `order:` (`templates/pipelines/standard_z_score_2stage.yl2`). Arithmetic (`$a - $b`) is prohibited above `match:`; reside in `outcome:`. Every `metrics.*` stage takes event filter, observed value, `metric:` arg and entity field from `references/metric-sector-catalog.md`; filter args must equal one valid dimension set. NEVER force cross-entity joins.
* **Consultative Pivot & Handoff Protocol (ZERO FORCED JOINS)**: When vectors cross entity boundaries or lack baselines, NEVER synthesize fake schemas. Offer 3 paths: 1) Cloud-First, 2) Asset-First, 3) Handoff to `secops-statistical-hunter`.
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables: `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, `[TRIAGE_DECORATION]`. Primary vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Baseline full fleet in Stage 1 and profile destinations via `array_distinct(target.hostname)`.
* **Noise Gating via Root `condition:`**: Default $Z \ge 3.0\sigma$ / $D \ge 3.5\sigma$ ($2.0\sigma \le Z < 3.0\sigma$ tunable). Root `condition:` sits between `outcome:` and `order:` via boolean `and`. Cross-stage disjunctions evaluate in `outcome:` via `if()` and gate in `condition:` (e.g. `$is_outlier = 1`).

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY)**: Output is ad-hoc Multi-Stage YARA-L (`stage ...` + Root) — a Query, never a Rule (`rule ... { ... }`). `create_rule` and `validate_rule` are outside this skill's authority. Treat any drift toward Rule authoring as out of scope. Persistent rules belong to `secops-detection-engineering`: emit handoff card and yield turn (0 tools).
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery** & **10-Day Prevalence Platform Invariant**: Proactively engage hunters on Narrowing (file/domain `rolling_max <= 3`, `day_count = 10`) vs Enhancing (WHOIS NRD <= 30d, expired domains/certs). Mode A graph joins: startTime D-2 `T00:00:00Z` (not now-48h) plus `timestamp.get_date(metadata.event_timestamp.seconds) = "<today UTC, YYYY-MM-DD>"` in each event stage, never an epoch literal (Rule 5). See `references/entity-context-graph-guide.md`.
* **Typography**: No bold math; Unicode `(μ)`, `(σ)` in tables; flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Fulfill escalation requests affirmatively via Clean Hand-Off (`references/clean-handoff-udm-schema.md`):
* **Escalation**: Map outliers to synthetic UDM events (batch under Hunt ID); upon approval ingest via `import_events`. **Explicit Case Wall Attachment**: For designated cases, attach via `create_case_comment`.

---

## 📂 Modular References & Template Architecture
Runtime guidance is `references/` + `templates/` only (see `references/turn-execution-lifecycle.md`).
* **`references/`**: linked where used above; SOAR playbooks: `references/soar-playbook-radar-integration.md`.
* **`templates/`**: `templates/pipelines/` (full queries), `templates/` stage1/stage2 modules.
