---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
description: UEBA behavioral threat hunting via 30d SecOps metrics DAGs.
compatibility: Requires Google SecOps with Risk Analytics and SecOps GUS MCP.
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes multi-sector statistical outlier hunting using 30-day Risk Analytics (`metrics.*`).

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **UEBA / 30-Day Baselines** (`metrics.*`) / **Behavioral Risk** / **Multi-Sector Fusion**: Execute this skill (`secops-risk-metrics-multistage`).
* **Dual-Layer Defense for Trickle Attacks**: Layer 1 is Mode B Longitudinal CUSUM Drift ($S_t^+ \ge 4.0\sigma$ on `metrics.dns_queries_total`); Layer 2 is handoff to `secops-statistical-hunter` ($CV \le 0.20$).
* **Sub-Second Jitter Boundary**: Metrics tables cannot compute sub-second deltas; for beaconing jitter, emit Skill Handoff Card to `secops-statistical-hunter` and yield turn (0 tools called).
* **Privileged Lateral Movement & Unseen Endpoints**: Bipartite user-host history requires bounded lookback over raw `USER_LOGIN` logs; emit **Skill Handoff Card** to `secops-statistical-hunter` (`intent: PRIVILEGED_LATERAL_EXPANSION`) and yield turn (0 tools called).
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

> **Expert Bypass Fast-Track Protocol**: When both scope/vector and statistical model are specified (e.g. *"Run CUSUM drift on Frank's DNS queries"*), bypass consultation and jump directly to Phase 1B Pre-Flight Card. Never delay experienced practitioners.

> **Progressively Disclosed Consultative Guidance**:
> When intent or vector is unspecified, inspect `references/consultative-worksheet.md`:
> - **Tier 1 (Known Knowns)**: Spikes/bursts (Basic Z / Piecewise CRI).
> - **Tier 2 (Known Unknowns / Static Rule Blind Spots)**: Trickles, dormancy breaks, drift (CUSUM, Hurdle, Hourly Z, Poisson Rarity).
> - **Tier 3 (Unknown Unknowns / Cross-Silo Anomalies)**: Orthogonal dispersion ($D \ge 3.5\sigma$ 360° Radar).
> Present a **Summary View** with **Threat Hypothesis**, **Recommended Method & Rationale**, and **Alternative Vectors**. On deeper inquiry, load domain sheets under `references/consultative/` (`data-exfiltration.md`, `identity-and-access.md`, etc.).

> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> In open-ended consultative inquiries (unspecified vectors), **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. NEVER emit candidate queries (```yara), probe tools, or request clearance on Turn 1. Yield turn (0 tools called) and present the **Summary View** asking: *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"*

### 🕸️ 360° Entity Behavioral Risk Radar & Multi-Sector Threat Fusion
When profiling multiple sectors (*"multi-sector fusion"*, *"visualize all risk vectors"*, *"360 health check"*), see `references/360-behavioral-radar-guide.md`.
* **Architecture**: Decoupled micro-queries (`templates/pipelines/radar_360_decoupled_sector.yl2`) across 5 canonical sectors (Auth, Cloud, Workspace, Network, DNS).
* **Query Continuity**: In candidate preview and Pillar 2, display single representative sector micro-query (`stage auth_risk` with `order: $z desc`). Auto-bypass Mode B.
* **Native Reporting**: If webview requested or in MCP/agentapi: render pure inline `<svg>` in Pillar 1 (zero `<agent-embed>`). Otherwise in Jetski: embed via `<agent-embed>`. Never mix surfaces. Client Tool (if present).

### ☁️ Cloud Telemetry Scope & Anti-Narrowing Invariant
* In service account cloud repository access (`resource_read_*`, `resource_written_*`), NEVER narrow to 1 product; use `templates/pipelines/cloud_repository_scope_dual_branch.yl2` with `($sa, $vendor, $product, $resource, $ip by 1d)`. Reads use `RESOURCE_READ` or `USER_RESOURCE_ACCESS` (never `USER_RESOURCE_READ`).

### 🎯 CTI & Threat Report Mapping
**Map to UEBA Metric Tables**: Map to tables (`metrics.*`). **Transition Directly to Phase 1B**: Emit Pre-Flight Card & Literal Query Preview. **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (or responding to Phase 1A with *"yes to both"*, or via CTI mapping):
1. **Turn 1 Tool Invariant**: Zero external inspection; `references/` & `templates/` permitted. Permitted: name spot-check and exactly one 1-shot compiler probe (`udm_search`) on primary baseline filter (max 1 retry if error; in hybrid/dual-plane hunts, probe only primary baseline stream; never probe secondary streams on Turn 1).
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs vs Display Names*: Display names (with spaces) are NOT `user.userid`. First names (`frank`) must be spot-checked in UDM.
   - *14-Day UDM Spot-Check*: `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase', startTime: "<ISO_14D_AGO>", endTime: "<ISO_NOW>", maxEvents: 5)`.
   - *HARD RESOLUTION GATE (ZERO GUESSING & NO SPEC CARD)*: If 0 events match, **NEVER GUESS A USERNAME AND NEVER EMIT PRE-FLIGHT CARD**. **HALT IMMEDIATELY (0 tools called)**, asking: *"I could not resolve an active technical `user.userid` for '<Name>' in recent UDM telemetry. What is their corporate email or technical username?"*
3. **Clarification Resumption Protocol**: On receiving clarified username, present Pre-Flight Card and candidate query preview, then request Mode A/B clearance.
4. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope:  [Target User/Host ID or Fleet]
   • Threat Hypothesis:      [Operational hypothesis summary]
   • Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, 30d)
   • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode:[Mode A: 24h OR Mode B: 14d]
   • Statistical Model:      [Model & Operational Function, e.g. CUSUM Drift (Slow Accumulation)]
   • Significance Threshold: [Z >= 3.0σ (High Confidence) | 2.0σ <= Z < 3.0σ (Investigative Band) | D >= 3.5σ]
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)* & *Tool-Precondition Code Block Embargo*: Execute 1-shot pre-preview compiler probe with ISO 8601 timestamps: `secops-gus:udm_search(query="<single_event_udm_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. (Relative 'now-10m' is invalid). Multi-stage YARA-L in `udm_search` is PROHIBITED (causes 400). In hybrid queries, probe primary baseline stream only. Display query in markdown ONLY if probe compiles cleanly (200 OK). Emitting ```yara without an immediate preceding successful probe is STRICTLY PROHIBITED (applies universally to queries, pivots, and handoff cards).
   * *HARD PRE-FLIGHT CLEARANCE GATE (NO QUERY = NO CLEARANCE)*: Clearance Request (Step 5) MUST NEVER BE ASKED unless a valid, compilable multi-stage YARA-L query has been successfully probed (200 OK) and displayed under the Pre-Flight Card on that turn. If query cannot be probed, HALT immediately.
   * *Peer Cohort & Roster*: List cohort entities; if $N < 7$, flag `⚠️ Sparse Baseline Caution (N < 7)`. Peer Cohort Roster Requirement applies.
   * *Interactive Entity Graph Dimension Mandate*: Express joins under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Noise Level & Significance Threshold Steering (Active Root-Stage Condition Gating)*: Default: $Z \ge 3.0\sigma$ / $D \ge 3.5\sigma$. Guide analyst that sensitivity is tunable: High Confidence ($Z \ge 3.0\sigma$), Investigative Band ($2.0\sigma \le Z < 3.0\sigma$), Directional ($Z \le -3.0\sigma$), or Multi-Vector ($D^2 \ge 16.0$). Enforced in root-stage `condition:` (e.g. `condition: $z >= 2.0 and $z < 3.0`) before `order:`.
   * *Canonical Preview & Two-Phase Chained Hunt Specification*: Cross-entity hunts emit Two-Phase Chained Hunt Specification: Phase 1 (UEBA Outlier), Bridge Contract ($host, $timestamp, $user, $caller_ip), and Phase 2 (Targeted Cloud UDM Query).
5. **Explicit Clearance Question & Turn Termination (GATED ON STEP 4 QUERY DISPLAY)**: If target date specified, ask: *"Proceed with executing for [Target Date] now?"*. Otherwise ask: *"Would you like me to proceed with **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline)**? (Adjust noise level/significance threshold before execution if desired.)"*. STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN. Clearance question MUST be the final sentence of Turn 1. Calling execution tools on Turn 1 is STRICTLY PROHIBITED.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 6-Pillar Report (After Clearance) (MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT)

1. **Execution Telemetry Retrieval Mandate**: On explicit Mode A/B clearance, execute single-event `udm_search(query="<single_event_udm_filter>")`. Multi-stage YARA-L in `udm_search` is PROHIBITED (causes 400); multi-stage belongs in Pillar 2.
2. **Deterministic 6-Pillar Report Structure**: Synthesize findings into the complete 6-pillar report:
#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) (`window: 30d`). Single visual surface: <agent-embed> in Jetski (`run_command` present); <svg> in MCP/webview; Client Tool (if present); ASCII on request. Zero data-uri or raw SVG in chat Markdown. Unicode magnitude bars (`▰▰▰▰▱▱▱▱`).
#### 2. Executed Multi-Stage YARA-L Query: Verbatim mirror approved Turn 1 candidate query block. For 360 Radar, display executed sector micro-queries (representative micro-query `stage auth_risk` with `order: $z desc`; never `events:`, `$e.`, `rule ... { ... }`, or `math.sqrt`). Raw event filters (e.g. `principal.user.userid = ...`) are STRICTLY PROHIBITED in Pillar 2.
#### 3. Ranked Outlier Summary & Provenance Stamp: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`. Stamp execution provenance (events scanned, query execution time, projected schema columns).
#### 4. Forensic Vector Breakdown: Threat translation, scenarios, SOC playbook.
#### 5. Chronicle UI Manual Pivot (Triage Reference Only): Passive UDM filter for Chronicle UI (tool execution is STRICTLY PROHIBITED).
#### 6. Collapsible Technical Appendix (Statistical & Mathematical Appendix): Formulation ($N=30d$), CRI, $D = \sqrt{\sum Z^2}$.
3. **Zero-Telemetry Clean Hunt Exemption (True Negative Audit Summary)**: When post-clearance `udm_search` returns 0 events (`{}`/`[]`), emit a 2-Section Clean Hunt Audit:
   - `#### 1. Statistical Outlier Report: [Target Metric] (Nominal Baseline)`: 0 observed events ($Z = 0.00\sigma, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline**).
   - `#### 2. Executed Multi-Stage YARA-L Query`: Literal query and scope.
   - **Pillars 3, 4, 5, and 6 are explicitly waived** (no speculative scenarios, pivots, or empty tables).

### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT))
* **Entity Shift**: When analyst asks for *"same query for"*, retain Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT) and Re-enter State 1 for new entity.
* **Federated Bridge**: When micro-math requested, emit Skill Handoff Card to `secops-statistical-hunter`.
* **Clean Escalation**: Promotion occurs on explicit confirmation.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)**:
  1. **Zero Data Simulation (NEVER Fabricate Data)** / **Zero Generative Simulation & Strict Data Grounding Contract**: Every score, count, timestamp MUST come from executed tool output. Simulating baselines or fabricating numbers is a CRITICAL TRUTH-IN-REPORTING FAILURE. Observed events come from `secops-gus:udm_search(query="<single_event_udm_filter>")`. Baselines ($\mu, \sigma$) and $Z, \text{CRI}$ come from baseline model. If empty, report `0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`. (Truth Over Completion: 0 events is a valid hunt).
  2. **Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)**: Never invent UDM fields or uncompiled YARA-L grammar. Verified via compiler probe (`<ISO_10M_AGO>` to `<ISO_NOW>`).
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If API query fails, STOP IMMEDIATELY. Zero simulation.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION). Local arithmetic simulation is a CRITICAL COMPLIANCE VIOLATION. Author natively via SecOps GUS MCP, Markdown.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. 100% self-contained.
* **Multi-Turn Continuity & Follow-Up Mandate**: On follow-up turns shifting entity or time ("same query for"), MAINTAIN Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT). NEVER fall through to `secops-siem-search` or execute Pillar 5; NEVER degrade to raw log dumps. Re-enter State 1 for new entity.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Formulate single atomic YARA-L query for Pillar 2 and dispatch targeted UDM search to `udm_search(query="<event_filter>")`. Fracturing into piecemeal searches is STRICTLY PROHIBITED. 360° Radar queries 5 canonical sectors in parallel.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Pillar 2 must contain the literal, verbatim multi-stage YARA-L query block displayed in pre-flight preview without freehand modifications.
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: If `udm_search` returns `"events"` without `"stats"`, abort 6-Pillar formatting. Present auto-corrected query (via `MultiStageTemplateRouter`) or ask to execute.

### 2. Compiler & Architectural Invariants
* **Template-First Routing Mandate**: Queries MUST assemble from templates in `templates/pipelines/` via `MultiStageTemplateRouter`.
* **Zero-Hallucination Compiler Grammar Contract**:
  - *Entity Role & Match Binding Invariant*: Match blocks accept ONLY simple bound identifiers ($host by 1d, $user by 1d), NEVER member access ($e.principal.asset.hostname in match: is invalid). Variables in match: MUST bind first in predicates ($host = principal.asset.hostname; $user = target.user.userid; $entity = principal.user.userid).
  - *Compiler Structural Boundary*: Arithmetic (`$a - $b`) STRICTLY PROHIBITED above `match:`. Derivations reside in `outcome:` below `match:`.
  - *Syntax Invariants*: No `in ("A", "B")` (use `%list`/`or`); no member dot-notation in `match:`; no `events:`; no `sqrt(...)` (use `$dist_sq`); no `by 24h` (use `by 1d`); `if(cond, then, else)` in `outcome:` requires 3 args; safe divisors via `$safe_std = if($std > 0, $std, 0.001)` or `+ 1.0`.
  - *Mandatory Companion Dimensions & Entity Affinity*: Cloud CRUD (`metrics.resource_*`) requires `metadata.vendor_name` and `metadata.product_name`. File metrics (`metrics.file_executions_*`) are Host/Binary scoped (`$host, $sha256`) requiring `metadata.event_type`. NEVER bind `principal.user.userid` to file metrics or force cross-entity joins.
* **Consultative Pivot & Handoff Protocol (ZERO FORCED JOINS)**: When vectors cross entity boundaries or lack user baselines, NEVER synthesize fake schemas. State boundary and offer 3 paths: 1) Cloud-First Pivot, 2) Asset-First Pivot (`file_executions_total`), or 3) Handoff to `secops-statistical-hunter`.
  - *Max 4 Joins Invariant (ZERO MONOLITHIC JOINS — maxJoinCount=4 & Inner-Join Drop)*: Limits queries to <= 4 joins (`maxJoinCount = 4`). Never fuse >= 3 orthogonal sectors into a single query (`STAT_ANTIPATTERN_MONOLITHIC_RADAR_JOIN`; auto-bypass Mode B).
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables must be `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, or `[TRIAGE_DECORATION]`. Primary vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Multi-stage joins are inner joins. Baseline full fleet in Stage 1 and profile destinations via `array_distinct(target.hostname)`.
* **Noise Gating via Root `condition:`**: Root stage natively supports `condition:` for post-aggregation filtering before `order:`. Compound expressions valid (`condition: $z_score >= 3.0`, `condition: $z_score >= 2.0 and $z_score < 3.0`). Invariant: placed strictly AFTER `outcome:` and BEFORE `order:`.

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: Zero Streaming Detection Rule Syntax (`create_rule` and `validate_rule` are STRICTLY PROHIBITED). Output ad-hoc Multi-Stage YARA-L (`stage ...` + Root) for threat hunting. Outputting streaming rules is a **CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION**.
* **Strict Nomenclature Mandate**: Ad-hoc hunt logic is a Query, never a Rule (CRITICAL NOMENCLATURE VIOLATION).
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery** & **10-Day Prevalence Platform Invariant**: Bind Entity Graph dimensions (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity; `day_count = 10`) into Stage 2 on demand.
* **Typography Invariants**: No bold math (`$+4.16\sigma$`); Unicode `(μ)`, `(σ)` in tables; flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Triggered ONLY on analyst request (*"escalate"*, *"open a case"*):
* **Path A: General Escalation (No Case ID)**: Preview synthetic JSON, confirm ingestion with analyst (yield turn, 0 tools), then execute `secops-gus:import_logs`.
* **Path B: Explicit Case Wall Attachment (Case ID specified)**: Call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` and confirm.

---

## 📂 Modular References & Template Architecture
* **`references/`**: `references/consultative-worksheet.md`, `references/360-behavioral-radar-guide.md`, `references/clean-handoff-udm-schema.md`, `soar-playbook-radar-integration.md`, `metrics-catalog.md`, `multi-stage-metrics-guide.md`, `compiler-submission-policy.md`
* **Pipelines & Scripts**: `templates/pipelines/`, `templates/stage1_extractors/`, `scripts/` (`template_router.py`, `radar_collector.py`)
