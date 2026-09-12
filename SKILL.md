---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
description: UEBA threat hunting via 30d SecOps metrics DAGs.
compatibility: Requires Google SecOps with Risk Analytics and SecOps GUS MCP.
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes multi-sector outlier hunting using 30-day Risk Analytics (`metrics.*`).

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **UEBA / 30-Day Baselines** (`metrics.*`) / **Behavioral Risk** / **Multi-Sector Fusion**: Execute `secops-risk-metrics-multistage`.
* **Dual-Layer Defense for Trickle Attacks**: Layer 1 is Mode B Longitudinal CUSUM Drift ($S_t^+ \ge 4.0\sigma$ on `metrics.dns_queries_total`); Layer 2 is handoff to `secops-statistical-hunter` ($CV \le 0.20$).
* **Sub-Second Jitter Boundary**: Metrics tables cannot compute sub-second deltas; for beaconing jitter, emit Skill Handoff Card to `secops-statistical-hunter` and yield turn (0 tools called).
* **Privileged Lateral Movement & Unseen Endpoints**: Bipartite history requires raw `USER_LOGIN`; emit Skill Handoff Card to `secops-statistical-hunter` (`intent: PRIVILEGED_LATERAL_EXPANSION`) and yield turn (0 tools called).
* **Scheduled Exfiltration & Cron Periodicity Demarcation**: Daily metrics (`period: 1d`) cannot prove cron cadence. Offer: 1) Mode B Longitudinal CUSUM Drift (`longitudinal_cusum.yl2`) / Entity Graph prevalence (`references/multi-stage-metrics-guide.md`, section 29) for 30d accumulation; 2) For cron proof, emit **Skill Handoff Card** to `secops-statistical-hunter` (`intent: SCHEDULED_EXFILTRATION_TIMING`, evaluating raw `NETWORK_CONNECTION` $\Delta t / CV \le 0.20$) and yield turn (0 tools called).
* **Corporate Rollouts & Patch Tuesday Normalization**: For unfamiliar binary bursts, deploy Archetype 3 Fleet Prevalence Normalization (`templates/pipelines/hybrid_metric_fleet_prevalence_2stage.yl2`) with token matching (`$token by 1d` on `target.process.file.sha256 = $token`) and linear dampener `1.0 / (k_fleet + 1.0)`, or handoff to `secops-statistical-hunter` (`intent: FLEET_PREVALENCE_NORMALIZATION`).
* **Non-Metrics Telemetry Steering Mandate** (Git, raw UDM): Emit **Skill Handoff Card** and steer to `secops-statistical-hunter`.
* **Zero-Code Handoff Invariant**: Never emit candidate YARA-L with a Skill Handoff Card; Handoff cards are strictly conceptual; code belongs to destination skill.

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: 24h window vs 30d baseline (`window: 30d`). Target dates (e.g. "Aug 12") auto-bypass Mode B.
2. **Mode B: 30-Day Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**: Multi-day horizon (`match: $entity by 1d`). Tracks daily evolution and drift.

---

## 💡 How Risk Metrics Multi-Stage Analytics Work
3-step **Execution Framework Summary**: 1. **30d Baselines** (`metrics.*`), 2. **Multi-Stage DAGs**, 3. **Statistical Framework** ($Z$, MAD, Poisson, $\Delta Z$, CUSUM, $D$). Ask for more information.

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE

### 🚦 State 1: Pre-Flight Clearance & Specification (Zero Execution on Turn 1) (MANDATORY STEP 1: PRE-FLIGHT CLEARANCE)

When a hunt is initiated, **NEVER CALL SEARCH TOOLS ON THAT TURN**.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B is **ONLY UNLOCKED** when **BOTH** are explicitly defined:
1. **Entity Scope** (user, cohort, fleet / cloud) **AND**
2. **Telemetry Vector(s)** (Cloud CRUD, Workspace, Net Egress, Endpoint, Auth).

> **Expert Bypass**: When scope/vector and model are specified (e.g. *"Run CUSUM on Frank's DNS"*), jump to Phase 1B Pre-Flight Card. When unspecified, consult `references/consultative-worksheet.md` (Tier 1 Spikes, Tier 2 Trickles/Drift, Tier 3 Orthogonal $D \ge 3.5\sigma$ 360° Radar). Present **Summary View** with **Threat Hypothesis**, **Recommended Method & Rationale**, **Alternative Vectors**.

> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> In open-ended consultative inquiries (unspecified vectors), **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. NEVER emit candidate queries (```yara), probe tools, or request clearance on Turn 1. Yield turn (0 tools called) and present the **Summary View** asking: *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"*

### 🕸️ 360° Entity Behavioral Risk Radar & Multi-Sector Threat Fusion
For multi-sector profiling (*"multi-sector fusion"*, *"360 health check"*), see `references/360-behavioral-radar-guide.md`.
* **Architecture**: Decoupled micro-queries (`templates/pipelines/radar_360_decoupled_sector.yl2`) across 5 canonical sectors (Auth, Cloud, Workspace, Network, DNS; all 5 must be reported).
* **Scope & Surface Alignment**: 5-spoke radial radar for single entities. Fleet sweeps: Ranked Outlier Bars or Heatmap Matrix (Mode B) evaluating all 5 canonical sectors: Auth, Cloud, Workspace, Network, DNS.
* **Query Continuity**: In preview and Pillar 2, display representative micro-query (`stage auth_risk` with `order: $z desc`). Auto-bypass Mode B on target dates.
* **Native Reporting**: Webview/MCP/agentapi: inline `<svg>` in Pillar 1; Jetski: `<agent-embed>`.

### ☁️ Cloud Telemetry Scope & Anti-Narrowing Invariant
* In service account cloud repository access (`resource_read_*`, `resource_written_*`), NEVER narrow to 1 product; use `templates/pipelines/cloud_repository_scope_dual_branch.yl2` with `($sa, $vendor, $product, $resource, $ip by 1d)`.

### 🎯 CTI & Threat Report Mapping
**Map to UEBA Metric Tables**: Map to tables (`metrics.*`). **Transition Directly to Phase 1B**: Emit Pre-Flight Card & Literal Query Preview. **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (or responding to Phase 1A with *"yes to both"*, or via CTI mapping):
1. **Turn 1 Tool Invariant**: Zero external inspection; name spot-check and 1-shot compiler probe (`udm_search`) on primary baseline filter permitted (max 1 retry; maximum 2 probes on Turn 1).
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs*: Display names (with spaces) are NOT `user.userid`.
   - *14-Day UDM Spot-Check*: `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase', startTime: "<ISO_14D_AGO>", endTime: "<ISO_NOW>", maxEvents: 5)`.
   - *HARD RESOLUTION GATE (ZERO GUESSING & NO SPEC CARD)*: If 0 events match, **NEVER GUESS A USERNAME AND NEVER EMIT PRE-FLIGHT CARD**. **HALT IMMEDIATELY (0 tools called)**, asking: *"I could not resolve an active technical `user.userid` for '<Name>' in recent UDM telemetry. What is their corporate email or technical username?"*
4. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope:  [Target User/Host ID or Fleet]
   • Threat Hypothesis:      [Operational hypothesis summary]
   • Baseline Horizon Spine: 30-Day (period: 1d, 30d)
   • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode:[Mode A: 24h OR Mode B: 14d]
   • Statistical Model:      [Model & Template, e.g. CUSUM Drift (`longitudinal_cusum.yl2`)]
   • Significance Threshold: [Z >= 3.0σ | 2.0σ <= Z < 3.0σ | D >= 3.5σ]
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)* & *Tool-Precondition Code Block Embargo*: Probe once with ISO 8601 UTC timestamps: `secops-gus:udm_search(query="<single_event_udm_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. Relative 'now-10m' is invalid. Display the query only on a clean 200 OK; emitting ```yara without an immediately preceding successful probe is STRICTLY PROHIBITED (applies universally to queries, pivots, and handoff cards).
   * *Peer Cohort & Roster*: List cohort entities; if $N < 7$, flag `⚠️ Sparse Baseline Caution (N < 7)`. Peer Cohort Roster Requirement applies.
   * *Interactive Entity Graph Dimension Mandate*: Express joins under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Noise Level & Significance Threshold Steering (Active Root-Stage Condition Gating)*: Default: $Z \ge 3.0\sigma$ / $D \ge 3.5\sigma$. Sensitivity is tunable: High Confidence ($Z \ge 3.0\sigma$), Investigative Band ($2.0\sigma \le Z < 3.0\sigma$), Directional ($Z \le -3.0\sigma$), or Multi-Vector ($D^2 \ge 16.0$). Enforced in root-stage `condition:` (e.g. `condition: $z >= 2.0 and $z < 3.0`) before `order:`.
   * *Model Concordance Invariant*: When declaring a statistical model, instantiate its template in `templates/stage2_math_models/` (see `references/model-concordance-guide.md`). Emitted `outcome:` derivations and `order:` clause MUST faithfully implement that template's mathematical AST signature (e.g. CUSUM `$cusum_drift_score`, Poisson `$poisson_z`, or Empirical Bayes `$posterior_mean`).
   * *Canonical Preview & Two-Phase Chained Hunt Specification*: Cross-entity hunts emit Two-Phase Chained Hunt Specification: Phase 1 (UEBA Outlier), Bridge Contract ($host, $timestamp, $user, $caller_ip), and Phase 2 (Targeted Cloud UDM Query).
5. **Clearance Question (final sentence of Turn 1, then yield)**: If target date specified, ask: *"Proceed with executing for [Target Date] now?"*. Otherwise ask: *"Would you like me to proceed with **Mode A (24-Hour Snapshot)** or **Mode B (14-Day Longitudinal Timeline)**? (Adjust noise level/significance threshold before execution if desired.)"*.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 6-Pillar Report (After Clearance) (MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT)

1. **State 2 Entry Condition**: If the preceding turn displayed a PRE-FLIGHT HUNTING SPECIFICATION card and the candidate multi-stage YARA-L query with its baseline filter probed clean (200 OK), Mode A/B clearance means execute now. Otherwise *"Mode A"*, *"Mode B"*, *"proceed"* are Phase 1A scope answers: emit card and preview, yield the turn.
2. **Execution Telemetry Retrieval Mandate**: On explicit Mode A/B clearance, execute single-event `udm_search(query="<single_event_udm_filter>")`. Multi-stage YARA-L in `udm_search` is PROHIBITED (causes 400); belongs in Pillar 2.
3. **Deterministic 6-Pillar Report Structure**: Synthesize findings into the complete 6-pillar report:
#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) (`window: 30d`). Single visual surface: <agent-embed> in Jetski (`run_command` present); <svg> in MCP/webview; Client Tool (if present); ASCII on request. Zero data-uri or raw SVG in chat Markdown. Unicode magnitude bars (`▰▰▰▰▱▱▱▱`). Surface routing and sanctioned-script policy: `references/chart-specifications-guide.md`.
#### 2. Executed Multi-Stage YARA-L Query: Verbatim mirror approved Turn 1 candidate query block. For 360 Radar, display executed sector micro-queries (representative `stage auth_risk` with `order: $z desc`; never `events:`, `$e.`, `rule ... { ... }`, or `math.sqrt`). Raw event filters (e.g. `principal.user.userid = ...`) are STRICTLY PROHIBITED in Pillar 2.
#### 3. Ranked Outlier Summary & Provenance Stamp: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`. Stamp execution provenance (events scanned, query execution time, projected schema columns).
#### 4. Forensic Vector Breakdown: Threat translation, scenarios, SOC playbook.
#### 5. Chronicle UI Manual Pivot (Triage Reference Only): Passive UDM filter the analyst runs in the Chronicle UI.
#### 6. Collapsible Technical Appendix (Statistical & Mathematical Appendix): ($N=30d$), CRI, $D = \sqrt{\sum \max(0, Z_i)^2}$ (`references/calibrated-risk-index-guide.md`).
4. **Zero-Telemetry Clean Hunt Exemption (True Negative Audit Summary)**: When post-clearance `udm_search` returns 0 events (`{}`/`[]`), emit a 2-Section Clean Hunt Audit:
   - `#### 1. Statistical Outlier Report: [Target Metric] (Nominal Baseline)`: 0 observed events ($Z = 0.00\sigma, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline**).
   - `#### 2. Executed Multi-Stage YARA-L Query`: Literal query and scope.
   - **Pillars 3, 4, 5, and 6 are waived** (360° radar profiles evaluate all 5 sectors with visual radar).

### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT))
* **Entity Shift**: On *"same query for"*, retain Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT) and Re-enter State 1 for new entity.
* **Federated Bridge**: When micro-math requested, emit Skill Handoff Card to `secops-statistical-hunter`.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Hunt Tool Contract**: An active hunt runs on `secops-gus:udm_search` alone — once to probe, once to execute; Clean Hand-Off adds `create_case_comment` / `import_logs` on explicit request. Behavioral truth lives in `metrics.*` 30-day baselines, the sole evidentiary substrate for every score reported. Case, alert, rule, and playbook state describes detections that already fired — a different question, and a different skill.
* **THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)**:
  1. **Zero Data Simulation (NEVER Fabricate Data)** / **Zero Generative Simulation & Strict Data Grounding Contract**: Every score, count, and timestamp MUST come from executed tool output; baselines ($\mu, \sigma$) and $Z, \text{CRI}$ come from the 30-day baseline model. Simulating baselines or fabricating numbers is a CRITICAL TRUTH-IN-REPORTING FAILURE. (Truth Over Completion: 0 events is a valid hunt.)
  2. **Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)**: Never invent UDM fields or uncompiled YARA-L grammar. Verified via compiler probe (`<ISO_10M_AGO>` to `<ISO_NOW>`).
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If API query fails, STOP IMMEDIATELY. Zero simulation.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION). Local simulation is a CRITICAL COMPLIANCE VIOLATION. Author natively via SecOps GUS MCP.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. 100% self-contained.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Formulate single atomic YARA-L query for Pillar 2; fracturing into piecemeal searches is STRICTLY PROHIBITED. 360° Radar queries 5 sectors in parallel.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Pillar 2 must contain the literal, verbatim multi-stage YARA-L query block displayed in pre-flight preview without modifications.
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: If `udm_search` returns `"events"` without `"stats"`, abort 6-Pillar formatting. Present auto-corrected query (via `MultiStageTemplateRouter`) or ask to execute.

### 2. Compiler & Architectural Invariants
* **Template-First Routing Mandate**: Queries MUST assemble from templates in `templates/pipelines/` via `MultiStageTemplateRouter`.
* **Zero-Hallucination Compiler Grammar Contract**:
  - *Entity Role & Match Binding Invariant*: Match blocks accept ONLY simple bound identifiers ($host by 1d, $user by 1d), NEVER member access ($s1.user or $e.host in match: is invalid). Variables in match: MUST bind first in predicates ($host = principal.asset.hostname; $user = target.user.userid).
  - *Compiler Structural Boundary*: Arithmetic (`$a - $b`) STRICTLY PROHIBITED above `match:`. Reside in `outcome:` below `match:`.
  - *Syntax Invariants*: No `in ("A", "B")` (use `%list`/`or`); regex uses `re.regex($var, /pat/)` or `$var = /pat/`; no member dot-notation in `match:`; no `events:`; no `sqrt(...)` (use `$dist_sq`); no `by 24h` (use `by 1d`); `if(cond, then, else)` requires 3 args; bind intermediate placeholders for compound math (e.g. `$val = $a + $b; $safe = if($cond, $val, $def)`).
  - *Mandatory Companion Dimensions & Entity Affinity*: Cloud CRUD (`metrics.resource_*`) requires `metadata.vendor_name`, `metadata.product_name`. File metrics (`metrics.file_executions_*`) are Host/Binary scoped (`$host, $sha256`) requiring `metadata.event_type`. NEVER bind `principal.user.userid` to file metrics or force cross-entity joins.
* **Consultative Pivot & Handoff Protocol (ZERO FORCED JOINS)**: When vectors cross entity boundaries or lack baselines, NEVER synthesize fake schemas. Offer 3 paths: 1) Cloud-First, 2) Asset-First, 3) Handoff to `secops-statistical-hunter`.
  - *Max 4 Joins Invariant (ZERO MONOLITHIC JOINS — maxJoinCount=4 & Inner-Join Drop)*: Limits queries to <= 4 joins (`maxJoinCount = 4`). Never fuse >= 3 orthogonal sectors into a single query (`STAT_ANTIPATTERN_MONOLITHIC_RADAR_JOIN`; auto-bypass Mode B).
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables: `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, `[TRIAGE_DECORATION]`. Primary vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Baseline full fleet in Stage 1 and profile destinations via `array_distinct(target.hostname)`.
* **Noise Gating via Root `condition:`**: Root stage supports `condition:` post-aggregation before `order:` (e.g. `condition: $z >= 2.0 and $z < 3.0`). Placed strictly AFTER `outcome:` and BEFORE `order:`.

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY)**: Output is ad-hoc Multi-Stage YARA-L (`stage ...` + Root) — a Query, never a Rule. `create_rule` and `validate_rule` are outside this skill's authority. Streaming detection Rules are a different product surface: converting a hunt into a Rule discards the 30-day baseline comparison this skill exists to perform, and hands the task to a different skill. Treat any drift toward Rule authoring as out of scope and say so.
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery** & **10-Day Prevalence Platform Invariant**: Bind Entity Graph dimensions (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity; `day_count = 10`) into Stage 2 on demand.
* **Typography Invariants**: No bold math; Unicode `(μ)`, `(σ)` in tables; flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Fulfill requests to alert, notify, or escalate (*"create a UDM alert"*, *"alert on this"*, *"send this in"*, *"escalate"*, *"open a case"*, *"generate synthetic event"*, *"handoff"*) affirmatively via Clean Hand-Off. Load `references/clean-handoff-udm-schema.md` for multi-event schemas:
* **Path A: General Escalation**: Map outliers to synthetic UDM events (batch under Hunt Campaign ID). Preview card (yield turn, 0 tools). Upon approval, direct Chronicle API ingestion.
* **Path B: Explicit Case Wall Attachment (Case ID specified)**: When an active case is designated (*"attach to Case 11075"*), call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` and confirm.

---

## 📂 Modular References & Template Architecture
* **`references/`**: `consultative-worksheet.md`, `360-behavioral-radar-guide.md`, `clean-handoff-udm-schema.md`, `soar-playbook-radar-integration.md`, `metrics-catalog.md`, `multi-stage-metrics-guide.md`, `compiler-submission-policy.md`, `model-concordance-guide.md`, `calibrated-risk-index-guide.md`, `chart-specifications-guide.md`, `statistical-models-taxonomy.md`, `statistical-hunting-cooperative-framework.md`
* **Pipelines & Scripts**: `templates/pipelines/`, `templates/stage1_extractors/`, `template_router.py`, `radar_collector.py`
