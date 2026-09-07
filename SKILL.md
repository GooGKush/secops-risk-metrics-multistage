---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
description: |
  Multi-stage statistical outlier hunting in Google SecOps using Risk Analytics metrics (`metrics.*`) DAGs.
  Triggers: "hunt with risk metrics", "multi-stage outlier", "MAD on network bytes", "z-score on auth", "fleet outlier", "multi-sector fusion", "360 risk radar", "same query for".
compatibility: Requires Google SecOps with Risk Analytics and SecOps GUS MCP.
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes multi-sector statistical outlier hunting using 30-day Risk Analytics metrics (`metrics.*`).

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **30-Day Baselines** (`metrics.*`) / **Peer Cohorts** / **Multi-Sector Fusion**: Execute this skill (`secops-risk-metrics-multistage`).
* **Dual-Layer Defense for Trickle Attacks**: Layer 1 is Mode B Longitudinal CUSUM Drift ($S_t^+ \ge 4.0\sigma$ on `metrics.dns_queries_total`); Layer 2 is handoff to `secops-statistical-hunter` ($CV \le 0.20$).
* **Sub-Second Jitter Boundary**: Metrics tables (`metrics.*`) cannot compute sub-second deltas. For beaconing jitter or raw connection deltas, emit Skill Handoff Card to `secops-statistical-hunter` and yield turn (0 tools called).
* **Non-Metrics Telemetry Steering Mandate** (Git repos, raw UDM): Emit **Skill Handoff Card** and steer to `secops-statistical-hunter`.
* **Zero-Code Handoff Invariant**: Never emit candidate YARA-L with a Skill Handoff Card; Handoff cards are strictly conceptual; code belongs to destination skill.

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: 24h window vs 30d baseline (`window: 30d`). Evaluates current outliers (1 row/entity). Target dates (e.g. "Aug 12") auto-bypass Mode B.
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

> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> If analyst specifies entities but omits telemetry vector, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. Yield turn and ask: *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"*

### 🕸️ 360° Entity Behavioral Risk Radar (All-Vectors / Radial Profiling)
When profiling an entity across all vectors (*"visualize all risk vectors"*, *"360 health check"*), consult `references/360-behavioral-radar-guide.md`:
1. **Mandatory 5-Sector Roster**: Canonical metric functions: Auth (`metrics.auth_attempts_success`), Cloud (`metrics.resource_creation_total`), Workspace (`metrics.workspace_total_download_actions`), Net (`metrics.network_bytes_outbound`), DNS (`metrics.http_queries_total`).
2. **Compilable Micro-Query Template (ZERO MONOLITHIC JOINS — maxJoinCount=4 & Inner-Join Drop)**: Decoupled per sector (`templates/stage1_extractors/` or `references/multi-stage-metrics-guide.md`). Bind genuine UDM event types (`$b.metadata.event_type = "USER_LOGIN"`) and real metric functions (`stage auth_risk` matching `$user by 1d` with `order: $z desc`). Preview and Pillar 2 MUST display ONLY this single representative sector query in ```yara (never join 2+ sectors; joins cause silent inner-join drops).
3. **Visualization Strategy (Single visual surface: Embed OR Inline SVG OR Tool)**:
   - **Adaptive Single-Surface Routing (NEVER Render Both ASCII & Visual)**:
     • *Jetski (`run_command` present)*: Output ONLY `<agent-embed src="file:///<artifact_dir>/<name>.html"></agent-embed>` and link via `scripts/radar_collector.py`. Zero data-uri or raw SVG in chat Markdown.
     • *MCP / Webview (no `run_command`)*: Emit inline `<svg viewBox="0 0 620 480">` in chat Markdown. Render ASCII ONLY on explicit request.
     • *Client Tool*: If tool declares radar/SVG, invoke with entity & sector scores.
   - **Canonical Layout**: Rings $+1\sigma$ to $+4\sigma$; spokes: Auth, Cloud, Workspace, Net, DNS. Scales: Z and CRI ($+3.0\sigma$).
4. **Post-Flight 5-Sector Verification & Euclidean Join Audit**:
   On Turn 2, affirm 5 sectors (Auth, Cloud, Workspace, Net, DNS) queried against 30d baselines via `udm_search` or `radar_collector.py` (quiet sectors $Z=0.00\sigma$, $\text{CRI}=0$). Join 5 sector Z-scores into Threat Distance $D = \sqrt{\sum_{i=1}^5 Z_i^2}$, render in Pillar 3/4 tables, and evaluate CRI ($D \ge 3.0\sigma \implies \text{CRI} \ge 50$). Never wrap math in bold (`**$+2.93\sigma$**` invalid; write `$+2.93\sigma$`). Consult `references/360-behavioral-radar-guide.md`.

### ☁️ Cloud Telemetry Scope & Anti-Narrowing Invariant
* **Anti-Narrowing Invariant for Cloud Data Stores**: When hunting service account cloud repository access (`resource_read_*`, `resource_written_*`), NEVER narrow to a single product: use `templates/pipelines/cloud_repository_scope_dual_branch.yl2` with `($sa, $vendor, $product, $resource, $ip by 1d)`. UDM parses `GCP_CLOUDAUDIT` into full lifecycle: CRUD (`RESOURCE_*`), user actions (`USER_RESOURCE_ACCESS/UPDATE_CONTENT/UPDATE_PERMISSIONS`), and IAM (`USER_CHANGE_PERMISSIONS`). Reads use `RESOURCE_READ` or `USER_RESOURCE_ACCESS` (never `USER_RESOURCE_READ`). Consult `references/metrics-catalog.md`.

### 🎯 CTI & Threat Report Mapping (Reports, URLs, CVEs, Threat Actors)
When analyst provides a threat report:
1. **Map to UEBA Metric Tables**: Map attack stages to tables (`metrics.*`).
2. **Transition Directly to Phase 1B**: Emit **Pre-Flight Hunting Specification Card** and **Literal Query Preview** on Turn 1. **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (or responding to Phase 1A with *"yes to both"*, or via CTI mapping):
1. **Turn 1 Tool Invariant**: Zero external inspection; `references/` & `templates/` permitted for syntax lookup. Permitted: name spot-check and 1-shot pre-preview compiler probe (`udm_search`).
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs vs Display Names*: Display names (with spaces) are NOT `user.userid`. Standalone first names (e.g. `greg`, `frank`) MUST be spot-checked in UDM before hunting.
   - *14-Day UDM Spot-Check*: `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase', startTime: "<ISO_14D_AGO>", endTime: "<ISO_NOW>", maxEvents: 5)`.
   - *HARD RESOLUTION GATE (ZERO GUESSING & NO SPEC CARD)*: If 0 events match or query fails, **NEVER GUESS A USERNAME AND NEVER EMIT PRE-FLIGHT CARD**. **HALT IMMEDIATELY (0 tools called)**, asking:
     > *"I could not resolve an active technical `user.userid` for '<Name>' in recent UDM telemetry. What is their corporate email or technical username?"*
     
4. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope:  [Target User/Host ID or Fleet]
   • Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, 30d)
   • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode:[Mode A: 24h OR Mode B: 14d]
   • Statistical Model:      [Model, e.g. Multi-Sector Fusion]
   • Significance Threshold: [Z >= 3.0σ (CRI >= 50) / D >= 3.5σ]
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)* & *Tool-Precondition Code Block Embargo*: Execute 1-shot pre-preview compiler probe with ISO 8601 timestamps: `secops-gus:udm_search(query="<single_event_udm_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. (Relative 'now-10m' is invalid). Pass single-event filter (e.g. `metadata.event_type = "PROCESS_LAUNCH"` or `metadata.event_type = "USER_LOGIN"`); multi-stage YARA-L in `udm_search` is PROHIBITED (causes 400). Parameters require `camelCase` (`query`, `startTime`, `endTime`, `maxEvents`); 0 events is a valid probe. Display query in markdown ONLY if probe compiles cleanly (200 OK). Emitting ```yara without an immediate preceding successful probe is STRICTLY PROHIBITED (applies universally to queries, pivots, and handoff cards). If probe fails, auto-correct or trigger Consultative Pivot.
   * *HARD PRE-FLIGHT CLEARANCE GATE (NO QUERY = NO CLEARANCE)*: Clearance Request (Step 5) MUST NEVER BE ASKED unless a valid, compilable multi-stage YARA-L query has been successfully probed (200 OK) and displayed under the Pre-Flight Card on that turn. If query cannot be probed, HALT immediately.
   * *Peer Cohort Roster Requirement (Peer Cohort & Roster)*: List cohort entities. If active days $N < 7$, flag `⚠️ Sparse Baseline Caution (N < 7)` in card spine.
   * *Interactive Entity Graph Dimension Mandate*: Express joins under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Canonical Preview & Two-Phase Chained Hunt Specification*: Cross-entity hunts emit Two-Phase Chained Hunt Specification: Phase 1 (UEBA Outlier), Bridge Contract ($host, $timestamp, $user, $caller_ip), and Phase 2 (Targeted Cloud UDM Query).
5. **Explicit Clearance Question & Turn Termination (GATED ON STEP 4 QUERY DISPLAY)**: Once verified query preview is displayed: If target date specified (e.g. "Aug 12"), auto-select Mode A and ask: *"Would you like me to proceed with executing this hunt for [Target Date] now?"*. Otherwise ask: *"Would you like me to proceed with **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline)**?"*. STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN. Clearance question MUST be the final sentence of Turn 1. Calling execution tools on Turn 1 or emitting 6-pillar report on Turn 1 is STRICTLY PROHIBITED.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 6-Pillar Report (After Clearance) (MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT)

1. **Turn 2 Telemetry Retrieval Mandate**: On clearance, execute single-event `udm_search(query="<single_event_udm_filter>")`. Multi-stage YARA-L in `udm_search` is PROHIBITED (causes 400); multi-stage belongs in Pillar 2. Zero `json_chart`.
2. **Deterministic 6-Pillar Report Structure**: Synthesize findings into the complete 6-pillar report:
#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) (`window: 30d`). Single visual surface: `<agent-embed>` in Jetski; `<svg>` in MCP; Client Tool (if present); ASCII on request. Unicode magnitude bars (`▰▰▰▰▱▱▱▱`).
#### 2. Executed Multi-Stage YARA-L Query: Formal multi-stage YARA-L 2.0 query for the hunt. For 360 Radar, display executed sector micro-queries. Raw event filters (e.g. `principal.user.userid = ...`) are STRICTLY PROHIBITED in Pillar 2.
#### 3. Ranked Outlier Summary & Provenance Stamp: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`. Stamp execution provenance (events scanned, query execution time, projected schema columns).
#### 4. Forensic Vector Breakdown: Threat translation, scenarios, SOC playbook.
#### 5. Chronicle UI Manual Pivot (Triage Reference Only): Passive UDM filter for Chronicle UI (tool execution is STRICTLY PROHIBITED).
#### 6. Collapsible Technical Appendix (Statistical & Mathematical Appendix): Formulation ($N=30d$), CRI, $D = \sqrt{\sum Z^2}$.

### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT))
* **Entity Shift Handling**: When analyst asks to *"run same for user X"*, *"what about admin?"*, retain Active Hunt Session Lock and Re-enter State 1 for new entity.
* **Federated Bridge to `secops-statistical-hunter`**: When analyst requests micro-math (MAD, CV beaconing jitter, Tukey fences), emit Skill Handoff Card to `secops-statistical-hunter`.
* **Clean Escalation**: Unsolicited case creation is prohibited; promotion occurs on explicit confirmation.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)**:
  1. **Zero Data Simulation (NEVER Fabricate Data)**: Every score, count, entity, timestamp MUST come from executed tool output. Zero Generative Simulation & Strict Data Grounding Contract: Observed events ($\text{Obs}$) come from `secops-gus:udm_search(query="<single_event_udm_filter>")` (single-event filter; do NOT pass multi-stage YARA-L). Baselines ($\mu, \sigma$) and $Z, \text{CRI}$ are calculated from the baseline model. If `{}` or empty, report `0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`. Fabricating numbers is a **CRITICAL TRUTH-IN-REPORTING FAILURE**. (Truth Over Completion: 0 events is a valid hunt).
  2. **Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)**: Never invent UDM fields or uncompiled YARA-L grammar. Every query must be verified via compiler probe (`<ISO_10M_AGO>` to `<ISO_NOW>`) before being asserted as valid.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, STOP IMMEDIATELY. Simulating baselines is STRICTLY PROHIBITED.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Detection runs inside Chronicle SIEM. Python simulation is a CRITICAL COMPLIANCE VIOLATION.
* **Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION)**: Post-search `run_command` (`scripts/radar_collector.py`) permitted SOLELY for Pillar 1 rendering.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. This skill is 100% self-contained.
* **Multi-Turn Continuity & Follow-Up Mandate**: On follow-up turns shifting entity or time ("same query for"), MAINTAIN Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT). NEVER fall through to `secops-siem-search` or execute Pillar 5; NEVER degrade to raw log dumps. Re-enter State 1 for new entity.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Single-vector hunts formulate the single atomic YARA-L query for Pillar 2 and dispatch targeted UDM search to `udm_search(query="<event_filter>")`. Cross-entity hunts use Two-Phase Chained Hunt Specification (Phase 1 UEBA ──► Bridge Contract ──► Phase 2 UDM). Fracturing into piecemeal raw searches is STRICTLY PROHIBITED. 360° Radar queries 5 canonical sectors in parallel.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Pillar 2 must contain the literal multi-stage YARA-L query matching the pre-flight candidate preview.
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: If `udm_search` returns `"events"` without `"stats"`, abort 6-Pillar formatting. Present auto-corrected query (via `MultiStageTemplateRouter`) or ask: *"Execute this auto-corrected query now, or exit?"*

### 2. Compiler & Architectural Invariants
* **Template-First Routing Mandate**: Queries MUST assemble from validated AST templates in `templates/pipelines/` via `MultiStageTemplateRouter`.
* **Zero-Hallucination Compiler Grammar Contract**:
  - *Entity Role & Match Binding Invariant*: Variables in `match:` MUST bind in event predicates (`target.user.userid` for logins; `principal.user.userid` for cloud/SaaS/net/proc; `principal.asset.hostname` for assets).
  - *Compiler Structural Boundary*: Arithmetic (`$a - $b`, `$a / $b`) STRICTLY PROHIBITED above `match:`. Derivations reside in `outcome:` below `match:`.
  - *Syntax Invariants*: No `in ("A", "B")` (use `%list`/`or`); no member dot-notation in `match:`; no `events:`; no `sqrt(...)` (use `$dist_sq`); no `by 24h` (use `by 1d`); no `if(...)` in outcome; dispersion floor `+ 1.0` in outcome divisors (`($obs - $avg) / ($std + 1.0)`); enums in `references/clean-handoff-udm-schema.md`.
  - *Mandatory Companion Dimensions & Entity Affinity*: Cloud CRUD (`metrics.resource_*`) requires `metadata.vendor_name` and `metadata.product_name`. File metrics (`metrics.file_executions_*`) are Host/Binary scoped (`$host, $sha256`) requiring `metadata.event_type`. NEVER bind `principal.user.userid` to file metrics or force cross-entity joins.
* **Consultative Pivot & Handoff Protocol (ZERO FORCED JOINS)**: When vectors cross entity boundaries or lack user baselines, NEVER synthesize fake schemas. State boundary and offer 3 paths: 1) Cloud-First 2-Phase Pivot, 2) Asset-First Pivot (`file_executions_total`), or 3) Handoff to `secops-statistical-hunter`.
  - *Max 4 Joins Invariant*: Limits queries to <= 4 joins (`maxJoinCount = 4`). Never fuse >= 3 orthogonal sectors into a single query (`STAT_ANTIPATTERN_MONOLITHIC_RADAR_JOIN`).
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables must be `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, or `[TRIAGE_DECORATION]`. Primary vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Multi-stage joins are inner joins. Baseline full fleet in Stage 1 and profile destinations via `array_distinct(target.hostname)`.

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: Zero Streaming Detection Rule Syntax (`create_rule` and `validate_rule` are STRICTLY PROHIBITED). Output ad-hoc Multi-Stage YARA-L (`stage ...` + Root) for threat hunting. Outputting streaming rules is a **CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION**.
* **Strict Nomenclature Mandate**: Ad-hoc hunt logic is a Query, never a Rule (CRITICAL NOMENCLATURE VIOLATION).
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery & 10-Day Prevalence Platform Invariant**: When requested, bind Entity Graph dimensions (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity; `day_count = 10`) into Stage 2.
* **Typography Invariants**: No bold math (`**$+4.16\sigma$**` invalid; write clean `$+4.16\sigma$`); Unicode `(μ)`, `(σ)` in tables. `$$\text{CRI} = \min(100, \max(0, \frac{Z}{3.0} \times 50))$$` and `$$D = \sqrt{\sum_{i=1}^5 Z_i^2}$$.` Flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Triggered EXCLUSIVELY on analyst request (*"escalate"*, *"open a case"*):
* **Path A: General Escalation (No Case ID)**: 1. Preview synthetic event JSON. 2. Ask *"Ingest this event into Chronicle SIEM to trigger automated case promotion?"* & **YIELD TURN (0 tools)**. 3. On confirmation, execute `secops-gus:import_logs`.
* **Path B: Explicit Case Wall Attachment (Case ID specified)**: Call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` and confirm.

---

## 📂 Modular References & Template Architecture
* **`references/`**: `clean-handoff-udm-schema.md`, `soar-playbook-radar-integration.md`, `metrics-catalog.md`, `multi-stage-metrics-guide.md`, `compiler-submission-policy.md`
* **Pipelines & Scripts**: `templates/pipelines/`, `templates/stage1_extractors/`, `scripts/` (`template_router.py`, `radar_collector.py`)
