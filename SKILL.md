---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
description: |
  Multi-stage statistical outlier hunting in Google SecOps using pre-computed Risk Analytics metrics (`metrics.*`) chained into 2-to-4 stage DAGs across 14 models.
  Triggers: "hunt with risk metrics", "multi-stage metrics outlier", "MAD on network bytes", "z-score on auth", "fleet outlier", "dual-baseline delta-z", "multi-sector threat fusion", "360 health check", "360 risk radar", "radial chart", "all risk vectors", "compare to team", "behavioral drift", "service account cloud repository access", "cloud CRUD baseline".
compatibility: Requires Google SecOps with Risk Analytics metrics enabled and the SecOps GUS MCP server (udm_search, get_operation).
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes **multi-sector statistical outlier hunting** using **30-day pre-computed Risk Analytics metrics (`metrics.*`)** chained into **2-to-4 stage DAG pipelines**.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **30-Day Baselines** (`metrics.*`) / **Peer Cohorts** / **Multi-Sector Fusion**: Execute this skill (`secops-risk-metrics-multistage`).
* **Non-Metrics Telemetry** (Git repos, raw UDM): Emit **Skill Handoff Card** and steer to `secops-statistical-hunter`.

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: 24h search window vs 30d baseline (`window: 30d`). Evaluates current outliers (1 row/entity).
2. **Mode B: 30-Day Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**: Multi-day horizon (`match: $entity by 1d`). Tracks daily evolution & CUSUM drift.

---

## 💡 How Risk Metrics Multi-Stage Analytics Work
When asked how analytics work: 1. **30d Baselines** (`metrics.*`), 2. **Multi-Stage DAG Analytics**, 3. **Execution Framework Summary** ($Z$, MAD, Poisson, $\Delta Z$, CUSUM, $D$). **Ask for more information** if you would like a deep dive on these behavioral models. *(See `references/statistical-models-taxonomy.md`)*

---

## 🚦 MANDATORY STEP 1: PRE-FLIGHT CLEARANCE & CONVERSATIONAL STAGING (ZERO EXECUTION ON TURN 1)

Whenever a hunt is initiated or parameters refined, **THE AGENT MUST NEVER CALL SEARCH OR INGESTION TOOLS ON THAT TURN**.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B (Query Preview & Spec Card) is **ONLY UNLOCKED** when **BOTH** requirements are explicitly defined:
1. **Entity Scope** (e.g. specific user, peer cohort, or enterprise fleet) **AND**
2. **Telemetry Vector(s)** (e.g. Cloud CRUD, Workspace downloads, Network Egress, Endpoint tools, or Auth).

> [!IMPORTANT]
> **Anti-Auth-Defaulting Guardrail & Conversational Break**:
> If an analyst specifies entities (*"compare user A to user B"*, *"check user X for deviations"*) but **omits the telemetry vector**, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. Yield the turn (Conversational Break) and ask:
> *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"*
> • ☁️ Cloud CRUD • 📁 Workspace • ⚙️ Endpoint Tools • 🌐 Network Egress • 🔑 Authentication • 🔀 Multi-Sector Fusion
> **STOP AND YIELD TURN (CONVERSATIONAL BREAK).** Analyst responses (*"yes to both"*, *"Cloud CRUD"*) **ONLY UNLOCK PHASE 1B** (Pre-Flight Card & Query Preview); they are NOT clearance to execute.

### 🕸️ 360° Entity Behavioral Risk Radar (All-Vectors / Radial Profiling)
When an analyst asks to profile an entity across all vectors (*"visualize all risk vectors"*, *"radial/spider chart"*, *"full spectrum profile"*, *"360 health check"*, *"behavioral fingerprint"*):
1. **Mandatory 5-Sector Roster**: Above Pre-Flight Card, present: 🔑 **Authentication & Access** (`metrics.auth_attempts_*`), ☁️ **Cloud Resource CRUD** (`metrics.resource_read_*`, `resource_written_*`, `resource_creation_total`), 📁 **Workspace & SaaS Exfiltration** (`metrics.workspace_*`), 🌐 **Network Egress** (`metrics.network_bytes_outbound`), 🌐 **DNS & Web Activity** (`metrics.dns_queries_fail` / `metrics.http_queries_total`; assets: `metrics.file_executions_*` with sha256).
2. **Compilable Micro-Query Template (ZERO CROSS-SECTOR JOINS)**:
   - Inner joins across sectors drop quiet accounts. Display the canonical decoupled micro-query:
   ```yara
   stage stage1_extract {
     metadata.event_type = "USER_LOGIN"
     target.user.userid = "%(entity_id)s"
     $user = target.user.userid
     match: $user by 1d
     outcome:
       $obs = count(metadata.id)
       $mu = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: "%(entity_id)s"))
       $sigma = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: "%(entity_id)s"))
   }
   $user = $stage1_extract.user
   match: $user by 1d
   outcome:
     $z_score = (max($stage1_extract.obs) - max($stage1_extract.mu)) / (max($stage1_extract.sigma) + 1.0)
   ```
3. **Visualization Strategy (Dual-Surface Context-Aware Architecture)**:
   - **MANDATORY GENERATIVE UI HTML RADAR**: In Pillar 1, execute `scripts/radar_collector.py --format dual --output <artifact_dir>/radar_<entity>.html` (pass deviations via `--scores` or `--data`). Output dual-surface embed block: `<agent-embed src="file:///<artifact_dir>/radar_<entity>.html"></agent-embed>`, Base64 data-URI `![360° Radar](data:image/svg+xml;base64,<b64>)`, link `[📊 Open 360° Risk Radar (SVG/HTML)](file:///<artifact_dir>/radar_<entity>.html)`, and CommonMark table with Unicode magnitude progress bars (`▰▰▰▰▱▱▱▱`). Drawing ASCII crosses or text art diagrams in chat is a CRITICAL VISUAL SPECIFICATION VIOLATION. In Jetski, `<agent-embed>` renders HTML; in MCP clients, Base64 data-URI renders SVG, preventing blackouts. Even for nominal entities ($Z=0.00\sigma$), the HTML/SVG artifact MUST be generated and embedded. Headless ASCII is strictly for SOAR comments (`create_case_comment`).
   - **Canonical 5-Spoke SVG Layout**: Center $(310, 260)$, max $r=125$. Rings: $r=31.25$ ($+1\sigma$), $62.5$ ($+2\sigma$), $93.75$ (`#d93025` $+3.0\sigma$), $125$ ($+4\sigma$). Polygon: `<polygon points="..." fill="rgba(26,115,232,0.25)" stroke="#1a73e8"/>` (red if $D \ge 3.0\sigma$). Layout `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 620 480">`.
   - **Sanitization Invariant**: NEVER output raw `<svg>` in markdown (stripped). Always emit `<agent-embed src="file:///<artifact_dir>/radar_<entity>.html"></agent-embed>` and Base64 data-URI image for universal client support.
   - **Mode B (14d Multi-Horizon)**: Render 360° Radial Radar ($Z_{\text{peak}}$) + 14-Day Timeline.
4. **Dual Scales**: Raw Z-score and CRI ($+3.0\sigma$ / CRI 50 perimeter; Section 6 formula).

### 🎯 CTI & Threat Report Mapping (Reports, URLs, CVEs, Threat Actors)
When an analyst provides a threat report (URL, CVEs, or threat actor):
1. **Map to UEBA Metric Tables**: Map attack stages to corresponding pre-computed metric tables (`metrics.*`).
2. **Transition Directly to Phase 1B**: Emit **Pre-Flight Hunting Specification Card** and **Literal Query Preview** on Turn 1. Ask for target scoping and **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (or responding to Phase 1A with *"yes to both"*, or via CTI mapping):
1. **ZERO Tool Execution**: 0 search/ingestion tool calls. *(Exception: 1 spot-check via `udm_search(user_display_name = "<name>" nocase)` permitted to resolve `user.userid`; MUST set `startTime: 1d ago` (≤24h lookback). Windows >24h trigger backend timeouts).*
2. **Plain-English Cyber Analogy (1–2 Sentences)**: Explain statistical approach using a physical concept.
3. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   *Render using high-contrast bold key-value formatting:*
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
   * *Mandatory Upfront Query Preview Protocol*: Display literal multi-stage YARA-L query in markdown prior to clearance.
   * *Peer Cohort Roster Requirement*: Resolve and list cohort entities and count in card (`• Peer Cohort & Roster: ...`).
   * *Interactive Entity Graph Dimension Mandate*: Express Entity Graph joins in card under `• Entity Graph Dimension: [Exact Filter]`.
   * *Interactive Entity Graph Rarity & Context Discovery*: Domain Rarity, Binary Rarity, IP Rarity (`rolling_max <= 3`), Fleet Prevalence (`day_count = 10`).
   * *10-Day Prevalence Platform Invariant*: Prevalence is hard-anchored to a 10-day lookback (`day_count = 10`).
   * *Canonical 2-Stage Preview Invariant*: No `events:` headers or `$e.`. Match variables bind to active fields (`target.user.userid` for auth, `principal.user.userid` for cloud/SaaS/net/proc, `principal.asset.hostname` for assets). Decouple into `stage stage1_extract` and root math (`+ 1.0` floor).
   * *Identity Disambiguation & Confirmation Protocol*: Display names (with spaces) are NOT `user.userid`. Resolve technical `userid` (e.g. `jholden`) in card (`• Target Entity / Scope: James Holden (Resolved User ID: jholden)`) and confirm in clearance question. If unresolved, prompt for `userid`.
4. **Explicit Clearance Question & Turn Termination**: Explicitly ask:
   > *"Would you like to run **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline with inception chart)**?"*
   *(If display name was provided, confirm the resolved or requested `userid` in question).*
   **STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN.**

---

## 📊 MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT (AFTER CLEARANCE)

*Pre-Output Tool Execution Guard*: On clearance, execute `udm_search` across sectors and `scripts/radar_collector.py` FIRST to write the artifact to disk. NEVER output markdown until the artifact exists. Even for nominal entities ($Z=0.00\sigma$), generate and embed nominal HTML/SVG. Zero ASCII crosses.
The report **MUST STRICTLY CONTAIN ALL 6 NUMBERED PILLARS**:
1. **Statistical Outlier Report**: `[Target Metric]` ([Statistical Model]) with 30-day baseline (`window: 30d`). (For 360° Radar: **MANDATORY GENERATIVE UI HTML RADAR** — Save to `<artifact_dir>/radar_<entity>.html`, embed inline via `<agent-embed src="file:///<artifact_dir>/radar_<entity>.html"></agent-embed>`, Base64 data-URI `![360° Radar](data:image/svg+xml;base64,...)`, link `[📊 Open 360° Risk Radar (SVG/HTML)](file:///<artifact_dir>/radar_<entity>.html)`, table with Unicode magnitude progress bars. ASCII strictly for SOAR comments).
2. **Executed Multi-Stage YARA-L Query**: Literal executed multi-stage YARA-L query string passed into `secops-gus:udm_search(query=...)`. (For 360° Radar: display compilable decoupled micro-query for primary outlier sector, e.g. Cloud CRUD or Auth; never cram multiple sectors into one stage). **Strict Nomenclature Mandate**: MUST be labeled 'Executed Multi-Stage YARA-L Query'. Calling ad-hoc query logic a 'Rule' or 'Hunting Rule' is a **CRITICAL NOMENCLATURE VIOLATION**.
3. **Ranked Outlier Summary**: Columns: `Entity`, `24h Observed`, `Baseline Mean`, `StdDev`, `Z-Score`, `CRI Score`, `Visual Magnitude`.
4. **Forensic Vector Breakdown**: Threat translation, significance, attack scenarios, SOC playbook.
5. **Immediate 1-Click Investigation Queries**: Raw UDM filter query for analyst drilldown.
6. **Statistical & Mathematical Appendix**: Formulation ($N = 30d$), CRI formula.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Zero Generative Simulation & Strict Data Grounding Contract**: Every metric number ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) MUST be directly extracted from `secops-gus:udm_search`. If `udm_search` returns `{}` or empty events, report `0 observed events`, `Z = 0.00σ`, and `🟢 Nominal Baseline`. Fabricating numbers is a **CRITICAL TRUTH-IN-REPORTING FAILURE**.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, STOP IMMEDIATELY and report the error. Simulating baselines locally is STRICTLY PROHIBITED.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Detection MUST run inside Chronicle SIEM. Simulating baselines locally in Python is a CRITICAL COMPLIANCE VIOLATION.
* **Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION & SIMULATION)**: Zero Python for queries/search. Post-search Python via `run_command` permitted SOLELY on sanctioned `scripts/radar_collector.py` to collate SIEM results. Never re-read internal validator scripts.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. This skill is 100% self-contained.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Single/dual-vector hunts dispatch the complete multi-stage DAG in a single atomic YARA-L query to `udm_search`. Breaking into isolated queries is STRICTLY PROHIBITED. 360° Radar queries the 5 canonical sector metric functions via decoupled micro-queries (`scripts/radar_collector.py` or parallel `udm_search`; $\le 5$ queries max). Zero Exploratory Log Fishing: Ad-hoc log dumps (raw Sysmon, Windows 4674, raw PROCESS_LAUNCH before metrics) are STRICTLY PROHIBITED.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Section 2 MUST contain the literal exact query string passed into `secops-gus:udm_search(query=...)`.
* **Zero Unsolicited Ingestion**: Zero ingestion via `import_logs` or `generate_synthetic_events`.
* **Post-Flight Audit & Auto-Correction**: If execution is deformed, present auto-corrected query and ask: *"Execute this auto-corrected query now, or exit?"*

### 2. Compiler & Architectural Invariants
* **Pre-Composed Pipeline Template Routing**: Route hunts directly to composite pipeline templates in `templates/pipelines/` (e.g. `mad_modified_z_2stage.yl2`, `standard_z_score_2stage.yl2`, `poisson_rarity_2stage.yl2`, `dual_sector_fusion_3stage.yl2`).
* **Zero-Hallucination Compiler Grammar Contract**:
  - *Entity Role & Match Binding Invariant*: Variables in `match:` MUST bind in event predicates (`target.user.userid` for logins; `principal.user.userid` for cloud/SaaS/net/proc; `principal.asset.hostname` for assets).
  - *Common Compiler Structural Boundary (Zero Event Arithmetic)*: Arithmetic (`$a - $b`, `$a / $b`) is STRICTLY PROHIBITED above `match:`. Placeholders bind directly to fields/scalar functions. ALL derivations and Z-scores reside in `outcome:` below `match:`.
  - *Syntax Invariants*: No `in ("A", "B")` (use `%list` or `or`); no dot-notation metric properties (`metrics.foo.mean` is INVALID, use `max(metrics.foo(...))`); no `by 24h` (use `by 1d`); linear outcome arithmetic (no nested `max(0,...)` or inline `sqrt(...)`); canonical metric names only: volumetric metrics end in `_total` (e.g. `metrics.resource_creation_total`; never invent `_count`).
  - *Mandatory Companion Dimensions*: All Cloud CRUD metrics (`metrics.resource_*`) strictly require both `metadata.vendor_name` and `metadata.product_name`. File execution metrics (`metrics.file_executions_*`) strictly require `metadata.event_type` and `principal.process.file.sha256`. Omitting companion dimensions causes Malachite compiler rejection (`unsupported filters for metric`).
  - *Max 4 Joins Invariant*: YARA-L 2.0 limits queries to $\le 4$ joins (`maxJoinCount = 4`). Each UEBA stage consumes 1 join; root joins consume $K-1$ joins. Stay within $\le 4$ joins. *(See `references/multi-stage-metrics-guide.md`)*.
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Every variable must fulfill `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, or `[TRIAGE_DECORATION]`. Primary threat vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`; bind them to active fleet rarity or Entity Graph constraints.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Multi-stage joins are inner joins. Evaluate full baseline in Stage 1 and profile destinations via `array_distinct(target.hostname)`.

### 3. Scope, Steering & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: `create_rule` and `validate_rule` are STRICTLY PROHIBITED during threat hunts.
* **Zero Ad-Hoc Entity Dossier Drift (MANDATORY 6-PILLAR REPORT & YARA-L EXECUTION)**: NEVER substitute generic entity overviews (`summarize_entity`, cases, alerts) for 6-Pillar report. Every profile MUST execute native multi-stage YARA-L, show literal query in Pillar 2, and render HTML/SVG radar in Pillar 1.
* **Zero Streaming Detection Rule Syntax (SEARCH-ONLY YARA-L DAG MANDATE)**: Output ad-hoc Multi-Stage YARA-L Search syntax (`stage name { ... }` + Root Stage) for Chronicle UDM Search (`udm_search`). Outputting continuous detection rules (`rule <name> { ... }`), `meta:`, or `condition:` blocks is a CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION.
* **Zero In-Query CRI Calculation (POST-PROCESSING ONLY MANDATE)**: Never evaluate CRI formulas in YARA-L. Compute raw scores ($Z$, $\text{MAD } Z$, Poisson, CUSUM, $D^2$) and order via `order: <score> desc`. CRI [0–100] is computed in Python post-processing.
* **Non-Metrics Telemetry Steering Mandate (HANDOFF TO STATISTICAL HUNTER)**: If an analyst targets non-baselined telemetry (e.g. Git repos, raw UDM), emit the **Skill Handoff Card** and steer to `secops-statistical-hunter`.
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY upon Direct Customer Request (On-Demand) or explicit Algorithmic Grounding.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)

### 1. Intent Routing: General Ingestion vs. Explicit Case Wall Attachment
* **Path A: General Escalation & Ingestion (Default when no Case ID is given)**: Ingest synthetic UDM security event to trigger dedicated case. NEVER pick an existing case via `list_cases` (CRITICAL PROCESS POLLUTION VIOLATION).
* **Path B: Explicit Case Wall Attachment (Carved-Out Exception for Active Case Work)**: Analyst specifies target case (*"Attach this finding to Case 11075"*). Call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` on that explicitly designated Case ID.

### 2. Mandatory Workflow per Path:
* **For Path A (Synthetic UDM Event Ingestion)**: 1. Preview event JSON from `references/clean-handoff-udm-schema.md`. 2. Ask *"Would you like me to ingest this event into Chronicle SIEM now to trigger automated case promotion?"* and **STOP CALLING TOOLS AND YIELD THE TURN**. 3. Upon confirmation, execute `secops-gus:import_logs` with `product_name: "SecOps Risk Metrics Hunter"`.
* **For Path B (Explicit Case Wall Comment)**: Call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` with user-provided `case_id` and confirm attachment.

---

## 📂 Modular References & Template Architecture
* **`references/`**: `metrics-catalog.md`, `statistical-models-taxonomy.md`, `calibrated-risk-index-guide.md`, `multi-stage-metrics-guide.md`, `compiler-submission-policy.md`
* **Pipelines & Scripts**: `templates/pipelines/`, `scripts/` (`radar_collector.py`, `submission_tests.py`)

