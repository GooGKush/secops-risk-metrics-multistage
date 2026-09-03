---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
description: |
  Multi-stage statistical outlier hunting in Google SecOps using pre-computed Risk Analytics metrics (`metrics.*`) chained into 2-to-4 stage DAGs.
  Triggers: "hunt with risk metrics", "multi-stage metrics outlier", "MAD on network bytes", "z-score on auth", "fleet outlier", "dual-baseline delta-z", "multi-sector threat fusion", "360 health check", "360 risk radar", "all risk vectors", "compare to team".
compatibility: Requires Google SecOps with Risk Analytics metrics enabled and the SecOps GUS MCP server (udm_search, get_operation).
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes **multi-sector statistical outlier hunting** using **30-day pre-computed Risk Analytics metrics (`metrics.*`)** in **2-to-4 stage DAGs**.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **30-Day Baselines** (`metrics.*`) / **Peer Cohorts** / **Multi-Sector Fusion**: Execute this skill (`secops-risk-metrics-multistage`).
* **Non-Metrics Telemetry Steering Mandate** (Git repos, raw UDM): Emit **Skill Handoff Card** and steer to `secops-statistical-hunter`.

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: 24h search window vs 30d baseline (`window: 30d`). Evaluates current outliers (1 row/entity).
2. **Mode B: 30-Day Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**: Multi-day horizon (`match: $entity by 1d`). Tracks daily evolution & CUSUM drift.

---

## 💡 How Risk Metrics Multi-Stage Analytics Work
Provide 3-step **Execution Framework Summary**: 1. **30d Baselines** (`metrics.*`), 2. **Multi-Stage DAGs**, 3. **Statistical Framework** ($Z$, MAD, Poisson, $\Delta Z$, CUSUM, $D$). Ask for more information / deep dive on behavioral models.

---

## 🚦 MANDATORY STEP 1: PRE-FLIGHT CLEARANCE (ZERO EXECUTION ON TURN 1)

Whenever a hunt is initiated, **NEVER CALL SEARCH OR INGESTION TOOLS ON THAT TURN**.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B (Query Preview & Spec Card) is **ONLY UNLOCKED** when **BOTH** are explicitly defined:
1. **Entity Scope** (specific user, peer cohort, or enterprise fleet) **AND**
2. **Telemetry Vector(s)** (Cloud CRUD, Workspace, Network Egress, Endpoint, or Auth).

> [!IMPORTANT]
> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> If an analyst specifies entities (*"compare user A to user B"*, *"check user X"*) but **omits the telemetry vector**, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. Yield turn and ask:
> *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"* (Cloud CRUD, Workspace, Endpoint Tools, Network Egress, Auth, Multi-Sector Fusion).
> Analyst answers ONLY unlock Phase 1B (Spec Card & Query Preview); they are NOT clearance to execute.

### 🕸️ 360° Entity Behavioral Risk Radar (All-Vectors / Radial Profiling)
When an analyst asks to profile an entity across all vectors (*"visualize all risk vectors"*, *"radial/spider chart"*, *"full spectrum profile"*, *"360 health check"*, *"behavioral fingerprint"*):
1. **Mandatory 5-Sector Roster**: Above Pre-Flight Card, present canonical metric functions:
   • 🔑 **Authentication & Access**: `metrics.auth_attempts_success` (`target.user.userid`)
   • ☁️ **Cloud Resource CRUD**: `metrics.resource_creation_total` (`principal.user.userid`, vendor: "Google Cloud Platform", product: "Google Cloud Platform")
   • 📁 **Workspace & SaaS**: `metrics.workspace_total_download_actions` (`principal.user.userid`)
   • 🌐 **Network Egress**: `metrics.network_bytes_outbound` (`principal.user.userid`)
   • 🌐 **DNS & Web Activity**: `metrics.http_queries_total` (`principal.user.userid`; assets: `metrics.file_executions_total` with sha256).
2. **Compilable Micro-Query Template (ZERO CROSS-SECTOR JOINS)**: Decoupled per sector (`stage stage1_extract` matching `$user by 1d` with `max(metrics.*)` and root `$z_score = ($obs - $mu) / ($sigma + 1.0)`). Avoid multi-vector inner joins that drop quiet entities.
3. **Visualization Strategy (Single visual surface: Client Tool OR Embed OR Inline SVG OR ASCII)**:
   - **Adaptive Single-Surface Routing (NEVER Render Both ASCII & Visual)**:
     • *Client Tool (if present)*: If any active tool declares radar/SVG visualization, invoke it with entity and computed sector Z-scores matching its parameter schema to render Pillar 1. Omit ASCII card. Detail in `references/chart-specifications-guide.md`.
     • *Jetski (`run_command` present)*: Run `python3 scripts/radar_collector.py --entity "%(entity)s" --scores "auth=<Z1>,cloud=<Z2>,workspace=<Z3>,net=<Z4>,dns=<Z5>" --output "<artifact_dir>/radar_%(entity)s.html" --format dual`. In Pillar 1, output ONLY `<agent-embed src="file:///<artifact_dir>/radar_%(entity)s.html"></agent-embed>` and link `[Open 360° Radar](file:///<artifact_dir>/radar_%(entity)s.html)`. Omit ASCII card.
     • *Generic MCP (no tool)*: In Pillar 1, emit pure inline `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 620 480">` directly in markdown.
     • *CLI / Plaintext*: Render ASCII radar card ONLY when analyst explicitly requests 'cli' or 'ascii'.
   - **Canonical SVG & ASCII Layout**: Rings: $+1\sigma$, $+2\sigma$, $+3\sigma$, $+4\sigma$. Spokes: Auth, Cloud, Workspace, Network, DNS/Web. CLI: Render text cross-axis radar card. Detail in `references/chart-specifications-guide.md`.
   - **Mode B (14d Multi-Horizon)**: Render 360° Radial Radar ($Z_{\text{peak}}$) + 14-Day Timeline.
4. **Dual Scales**: Raw Z-score and CRI ($+3.0\sigma$ / CRI 50 perimeter; Section 6 formula).

### ☁️ Cloud Data Store Scope & Anti-Narrowing Invariant
* **Anti-Narrowing Invariant for Cloud Data Stores**: When hunting service account cloud repository access (e.g. `resource_read_*`, `resource_written_*`), NEVER narrow to a single product (`BigQuery`/`Storage`). Route to `templates/pipelines/cloud_repository_scope_dual_branch.yl2` with dynamic `($sa, $vendor, $product, $resource, $ip by 1d)` to evaluate local baseline isolation and solve dynamic range masking (depth surges + zero-baseline dumps + origin host outliers).

### 🎯 CTI & Threat Report Mapping (Reports, URLs, CVEs, Threat Actors)
When an analyst provides a threat report (URL, CVEs, or threat actor):
1. **Map to UEBA Metric Tables**: Map attack stages to corresponding pre-computed metric tables (`metrics.*`).
2. **Transition Directly to Phase 1B**: Emit **Pre-Flight Hunting Specification Card** and **Literal Query Preview** on Turn 1. Ask for target scoping and **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (or responding to Phase 1A with *"yes to both"*, or via CTI mapping):
1. **Turn 1 Tool Invariant & Zero-File-Inspection Mandate**:
   Do NOT call `view_file`, `list_dir`, `grep_search`, or `find_by_name`. All metrics & patterns are in context.
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs*: Single-token account IDs without spaces (e.g. `expanse`, `fkolzig`, `srv-01`) are technical IDs. Proceed directly.
   - *Display Names*: Display names (with spaces) are NOT `user.userid`.
     • Execute AT MOST ONE spot-check (14d window): `udm_search(query='(target.user.user_display_name = "<name>" nocase or principal.user.user_display_name = "<name>" nocase) or (principal.user.first_name = "<First>" nocase and principal.user.last_name = "<Last>" nocase)', startTime: 14d ago, maxEvents: 5)`.
     • *Match Found ($\ge 1$ events)*: Extract verified `user.userid` (`target`/`principal`). In card: `• Target Entity / Scope: <Name> (Verified User ID: <id>)`.
     • *HARD RESOLUTION GATE (ZERO GUESSING)*: If 0 events match or query fails:
       **STRICTLY FORBIDDEN TO GUESS OR SYNTHESIZE A USERNAME** (no `first.last`, `f_last`, or heuristic abbreviations).
       **DO NOT GENERATE THE SPECIFICATION CARD OR DRAFT QUERIES.**
       **HALT IMMEDIATELY AND YIELD THE TURN (0 tools called)**, asking:
       > *"I could not resolve a technical `user.userid` for '<Display Name>' in recent UDM telemetry. What is their technical user ID / account identifier (e.g., username, sAMAccountName)?"*
       Wait for the analyst's answer before generating the Pre-Flight Card.
3. **Plain-English Cyber Analogy (1–2 Sentences)**: Explain statistical approach using a physical concept.
4. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   ```markdown
   ┌─────────────────────────────────────────────────────────────────┐
   │                PRE-FLIGHT HUNTING SPECIFICATION                 │
   │ • Target Entity / Scope:  [Target User/Host ID or Fleet]        │
   │ • Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, 30d) │
   │ • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]     │
   │ • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A] │
   │ • Evaluation Horizon Mode:[Mode A: 24h (Default) OR Mode B: 14d]│
   │ • Statistical Model:      [Model, e.g. Multi-Sector Fusion]     │
   │ • Significance Threshold: [Z >= 3.0σ (CRI >= 50) / D >= 3.5σ]   │
   └─────────────────────────────────────────────────────────────────┘
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)*: Display literal multi-stage YARA-L query in markdown prior to clearance.
   * *Peer Cohort Roster Requirement (Peer Cohort & Roster)*: Resolve and list cohort entities and count in card.
   * *Interactive Entity Graph Dimension Mandate*: Express joins in card under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Canonical 2-Stage Preview*: Match variables bind to active fields (`target.user.userid` for auth, `principal.user.userid` for cloud/SaaS/net/proc, `principal.asset.hostname` for assets). Decouple into `stage stage1_extract` and root math (`+ 1.0` floor).
5. **Explicit Clearance Question & Turn Termination**: Explicitly ask:
   > *"Would you like to run **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline with inception chart)**?"*
   **STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN.**

---

## 📊 MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT (AFTER CLEARANCE)

*Pre-Output Tool Execution Guard*: On clearance, execute the target pipeline (for 360° Radar: 5 parallel sector micro-queries). Emit findings into 6 numbered pillars. Zero `json_chart`.
The report **MUST STRICTLY CONTAIN ALL 6 NUMBERED PILLARS**:
1. **Statistical Outlier Report**: `[Target Metric]` ([Statistical Model]) with 30-day baseline (`window: 30d`). Single visual surface: Vector distribution/timeline for fleet hunts; 5-sector radar embed (<agent-embed> in Jetski, inline <svg> in generic MCP, ASCII radar in CLI; NEVER dual-render ASCII + visual) for 360° profiles with Unicode magnitude bars (`▰▰▰▰▱▱▱▱`). Detail in `references/chart-specifications-guide.md`.
2. **Executed Multi-Stage YARA-L Query**: Literal executed multi-stage YARA-L query string passed into `secops-gus:udm_search(query=...)`. (For 360° Radar: display compilable decoupled micro-query for primary outlier sector). Labeled 'Executed Multi-Stage YARA-L Query' (never 'Rule').
3. **Ranked Outlier Summary**: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`.
4. **Forensic Vector Breakdown**: Threat translation, significance, attack scenarios, SOC playbook. For fleet hunts with severe outliers ($Z \ge 3.0\sigma$), proactively suggest a 360° Behavioral Radar deep-dive.
5. **Immediate 1-Click Investigation Queries**: Raw UDM filter query for analyst drilldown.
6. **Statistical & Mathematical Appendix**: Formulation ($N = 30d$), single-line CRI formula, Euclidean distance norm $D = \sqrt{\sum Z^2}$.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Zero Generative Simulation & Strict Data Grounding Contract**: Every metric number ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) MUST be directly extracted from `secops-gus:udm_search`. If `udm_search` returns `{}` or empty events, report `0 observed events`, `Z = 0.00σ`, and `🟢 Nominal Baseline`. Fabricating numbers is a **CRITICAL TRUTH-IN-REPORTING FAILURE**.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, STOP IMMEDIATELY and report the error. Simulating baselines locally is STRICTLY PROHIBITED.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Detection MUST run inside Chronicle SIEM. Simulating baselines locally in Python is a CRITICAL COMPLIANCE VIOLATION.
* **Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION)**: Zero Python for detection/search. Client visual tools or post-search `run_command` (`scripts/radar_collector.py`) are permitted SOLELY for Pillar 1 rendering. Never re-read scripts or check Python versions.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. This skill is 100% self-contained.
* **Multi-Turn Continuity & Follow-Up Mandate**: On follow-up turns shifting entity or time parameters ("run same for user X", "look back 14d"), MAINTAIN the active Multi-Stage Risk Analytics architecture (30d baselines, DAGs, 6 pillars). NEVER degrade to raw log dumps.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Single/dual-vector hunts dispatch the single atomic YARA-L query atomically to `udm_search`. Fracturing into piecemeal searches is STRICTLY PROHIBITED. 360° Radar queries 5 canonical sector functions in parallel (<= 5 micro-queries). Each projects `$obs`, `$mu`, `$sigma`, `$z_score` in root `outcome:`. If a sector has 0 events or $Z \le 0$, record $0.00\sigma$, CRI 0; never fish for raw Sysmon/DNS/HTTP logs.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Section 2 MUST contain the literal exact query string passed into `secops-gus:udm_search(query=...)`.
* **Zero Unsolicited Ingestion**: Zero ingestion via `import_logs` or `generate_synthetic_events`.
* **Post-Flight Audit & Auto-Correction**: If execution is deformed, present auto-corrected query and ask: *"Execute this auto-corrected query now, or exit?"*

### 2. Compiler & Architectural Invariants
* **Pre-Composed Pipeline Template Routing**: Route hunts directly to composite pipeline templates in `templates/pipelines/` (e.g. `mad_modified_z_2stage.yl2`, `standard_z_score_2stage.yl2`, `poisson_rarity_2stage.yl2`, `dual_sector_fusion_3stage.yl2`).
* **Zero-Hallucination Compiler Grammar Contract**:
  - *Entity Role & Match Binding Invariant*: Variables in `match:` MUST bind in event predicates (`target.user.userid` for logins; `principal.user.userid` for cloud/SaaS/net/proc; `principal.asset.hostname` for assets).
  - *Common Compiler Structural Boundary (Zero Event Arithmetic)*: Arithmetic (`$a - $b`, `$a / $b`) is STRICTLY PROHIBITED above `match:`. Placeholders bind directly to fields/scalar functions. ALL derivations and Z-scores reside in `outcome:` below `match:`.
  - *Syntax Invariants*: No `in ("A", "B")` (use `%list` or `or`); no dot-notation metric properties (`metrics.foo.mean` is INVALID, use `max(metrics.foo(...))`); no `by 24h` (use `by 1d`); linear outcome arithmetic (no nested `max(0,...)` or inline `sqrt(...)`); canonical metric names end in `_total` (`metrics.resource_creation_total`).
  - *Mandatory Companion Dimensions*: Cloud CRUD metrics (`metrics.resource_*`) require `metadata.vendor_name` and `metadata.product_name`. File metrics (`metrics.file_executions_*`) require `metadata.event_type` and `principal.process.file.sha256`.
  - *Max 4 Joins Invariant*: YARA-L 2.0 limits queries to <= 4 joins (`maxJoinCount = 4`). Each UEBA stage consumes 1 join; root consumes K-1 joins.
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables must fulfill `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, or `[TRIAGE_DECORATION]`. Primary threat vectors MUST NEVER act solely as `[TRIAGE_DECORATION]` and must bind to active fleet rarity or Entity Graph constraints.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Multi-stage joins are inner joins. Evaluate full baseline in Stage 1 and profile destinations via `array_distinct(target.hostname)`.

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: Zero Streaming Detection Rule Syntax (`create_rule` and `validate_rule` are STRICTLY PROHIBITED). Output ad-hoc Multi-Stage YARA-L (`stage ...` + Root Stage) for `udm_search`. Outputting streaming rules is a **CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION**.
* **Strict Nomenclature Mandate**: Ad-hoc hunt logic is a Query, never a Rule. Calling a search query a 'Rule' is a **CRITICAL NOMENCLATURE VIOLATION**.
* **Mandatory 6-Pillar Report**: NEVER substitute generic dossiers (`summarize_entity`, cases, alerts) for 6-Pillar report. Every profile MUST execute native multi-stage YARA-L.
* **Zero In-Query CRI Calculation**: Compute raw scores in YARA-L. CRI [0–100] is computed in post-processing.
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery & 10-Day Prevalence Platform Invariant**: When requested, bind Entity Graph dimensions (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity; `day_count = 10`) into Stage 2.
* **KaTeX & Typography Invariants (ZERO PARSE FAILURES)**: No bold-wrapped math (`**$6.28\sigma$**` is invalid); use plain Unicode in tables `(μ)`, `(σ)`. Single-line linear formulas: `$$\text{CRI} = \min\left(100, \max\left(0, \frac{Z}{3.0} \times 50\right)\right)$$` and `$$D = \sqrt{\sum_{i=1}^5 Z_i^2}$$.` Flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)

> [!IMPORTANT]
> **Strict Escalation Gating Mandate (ZERO UNSOLICITED ESCALATION)**:
> Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**.
> This protocol is EXCLUSIVELY triggered when the analyst explicitly requests escalation, case creation, or ticketing (e.g. *"escalate this finding"*, *"send report to SecOps"*, *"open a case"*, *"ingest alert into SIEM"*).
> **NEVER append synthetic UDM events, event previews, or ingestion prompts to standard threat hunting reports or 360° behavioral profiles.** Standard hunt reports terminate cleanly at Pillar 6 (Appendix).

### Intent Routing & Mandatory Workflow (When Escalation Is Explicitly Requested):
* **Path A: General Escalation (No Case ID)**: 1. Preview synthetic event JSON. 2. Ask *"Would you like me to ingest this event into Chronicle SIEM now to trigger automated case promotion?"* and **STOP CALLING TOOLS AND YIELD THE TURN**. 3. Upon confirmation, execute `secops-gus:import_logs` (`product_name: "SecOps Risk Metrics Hunter"`). Never pick existing cases via `list_cases`.
* **Path B: Explicit Case Wall Attachment (Case ID specified)**: Call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` on designated ID and confirm.

---

## 📂 Modular References & Template Architecture
* **`references/`**: `metrics-catalog.md`, `statistical-models-taxonomy.md`, `calibrated-risk-index-guide.md`, `multi-stage-metrics-guide.md`, `compiler-submission-policy.md`
* **Pipelines & Scripts**: `templates/pipelines/`, `scripts/` (`radar_collector.py`, `submission_tests.py`)
